# C — Storage (read/query path)

**Owns:** everything between "a sealed bundle exists on disk" and "a caller has rows." Paginated grid
reads over the views, the detail queries behind a selected object, the counts behind chips and tiles,
and the two small projections (tree, live-to-stored lookup) that read `dim_object` directly. It ends
where a row becomes a view model.

**Not covered in this file:** the write half — see [`C-storage.md`](C-storage.md) for C1–C15. In
particular **C2** (view DDL) and **C4** (`DatabaseConnectionFactory`) are already mapped there and are
referenced, not re-described. What C4 buys this half is stated in the flow below.

## The flow

1. **A bundle is opened.** J calls `DatabaseConnectionFactory.OpenReadOnly` (**C4**). What the reader
   gets back is not a bare connection: the suppression sidecar is `ATTACH`ed, and two families of temp
   views exist on that handle — the suppression-dependent grid views and the asset-tier precedence
   views that shadow `main.dim_asset_tier`.
2. **That is the whole of how policy reaches a query.** No read component in this half knows
   suppression or policy tiers exist. `v_grid_findings` already excludes accepted findings;
   `dim_asset_tier` already resolves policy-over-derived. A query that named `main.dim_asset_tier`
   would get the capture's answer instead — which is what `EscalationPathRuleEvaluator` deliberately
   does, and what nothing in this half does.
3. **Health is read before data.** `DerivedHealthReader` (**C9**) answers "did analysis finish" from
   one metadata verdict. Per decision 0002 the read path is not supposed to probe for individual views
   to find out. It does anyway in three places — see Would-do-differently §5.
4. **A grid loads its first page.** J picks a `SortDefinition` from `SortRegistry` (**C19**) and builds
   a `GridFilter` (**C18**), then calls `KeysetQueryBuilder.Execute` (**C16**) with a view name, a
   column list, and a page size.
5. **The builder validates before it interpolates.** View name and every column are matched against
   `^[A-Za-z_][A-Za-z0-9_]*$`; the sort is asked to `Validate()`; filter values are bound as
   parameters. Only the `WithExists` subquery is embedded verbatim, under a stated security contract.
6. **It fetches `pageSize + 1` rows.** The extra row is how "there is a next page" is known without a
   second query. Key columns absent from the caller's `SELECT` list are appended so the cursor can be
   built.
7. **The cursor is issued as a `ContinuationToken`** (**C17**): grid id, sort id, a SHA-256 hash of the
   normalised filter, and the last row's key values, Base64-encoded.
8. **The next page presents the token back.** If sort or filter changed, `IsCompatibleWith` fails and
   the builder silently restarts at page 1 rather than returning rows from a different query's
   ordering.
9. **Counts are asked separately.** `KeysetQueryBuilder.CountRows` for the grid total;
   `GridSummaryQueryService` (**C22**) for filter chips; `DashboardQueryService` (**C23**) for tiles.
10. **A row is selected.** J hands the `object_guid` to `ObjectQueryService` (**C20**), which answers
    roughly thirty separate questions about it — identity, owner, group membership, delegation bundles,
    notes, tier, and permissions.
11. **Permissions take one of two routes.** `QueryAcesWithSource` first looks for a materialized ACL
    payload (**C12**'s format); if there is one, the answer is AD's applied DACL and
    `Source = MaterializedPayload`. If not, `InheritedAceResolver` (**C21**) walks the ancestor chain
    and reconstructs inheritance, and the result carries a warning saying it may not match AD exactly.
    **The caller is told which it got.**
12. **A finding is selected.** `ObjectQueryService` resolves evidence by discriminating on
    `fact_finding`'s source columns: `source_edge_id` set → control-edge evidence; `source_path_id` set
    → escalation-path evidence; both null → ACE evidence, gated on `context_json` naming it.
13. **The user tiers an object or accepts a finding.** `SetAssetTier` / `ClearAssetTier` (**C28**)
    write `dim_asset_tier_policy` in the **sidecar**, through a second connection the service was
    constructed with. `audit.db` is untouched, so the signature stays meaningful.
14. **The user saves a note.** `InsertNote` (**C28**) writes `dim_object_note` in **`audit.db`** —
    through the read-only connection. See Would-do-differently §3.

## Components

### C16 — Keyset paging engine
- **Layer:** Infrastructure
- **Owns:** turning a view name, a sort, a filter and a cursor into one page of rows plus the cursor
  for the next one.
- **Depends on:** C2, C4, C17, C18, C19
- **Implemented by:** `Paging/KeysetQueryBuilder.cs` (220), `Paging/KeysetPageResult.cs` (9)
- **Non-obvious:** it fetches `pageSize + 1` rows and discards the last — the extra row *is* the
  has-more signal, so no `COUNT` is needed to render a "next" affordance. Key columns missing from the
  caller's `SELECT` are silently appended, so a caller cannot break paging by asking for the wrong
  columns. `CountRows` is on the same type but is not keyset at all: it is a plain `COUNT(*)`,
  documented as returning **0 if the query fails** — the F-01-27 shape, in the paging layer, unfixed.

### C17 — Page cursor
- **Layer:** Infrastructure
- **Owns:** the opaque token that identifies a position in a specific query, and the rule for when that
  position is no longer meaningful.
- **Depends on:** C18
- **Implemented by:** `Paging/ContinuationToken.cs` (76)
- **Non-obvious:** the token carries a **filter hash**, not the filter. That is what makes "the user
  changed the filter mid-scroll" detectable rather than a silently corrupt result set — the cursor's
  key values would still be valid SQL against a different row ordering, and would skip or repeat rows
  without erroring. `Deserialize` returns `null` on any malformed input rather than throwing, so a
  hand-edited token degrades to page 1. `SchemaVersion` is written as the constant `1` at the only
  construction site and never compared.

### C18 — Grid filter algebra
- **Layer:** Infrastructure
- **Owns:** the set of predicate shapes a grid may express, their normalisation, their SQL, and their
  identity.
- **Implemented by:** `Paging/GridFilter.cs` (427)
- **Non-obvious:** filters are stored as a `SortedDictionary` keyed by a **type-prefixed column name** —
  `like:`, `notlike:`, `in:`, `notin:`, `maskonly:`, `gte:`, `orlike:`, `exists:` — which is what makes
  the hash stable regardless of the order predicates were added. The collation policy is deliberate and
  documented: `LIKE` uses `COLLATE NOCASE`, exact match uses binary, because SIDs and GUIDs must not
  case-fold. `WithExists` is the one method that embeds caller SQL verbatim; it carries an explicit
  security contract and a backstop rejecting `;`, `--` and `/*` — described in its own remarks as a
  backstop, not a licence.

### C19 — Approved sort catalogue
- **Layer:** Infrastructure
- **Owns:** the closed set of orderings any grid may use, each guaranteed to end in a unique
  tie-breaker.
- **Implemented by:** `Paging/SortRegistry.cs` (324), `Paging/SortRegistry.SecuritySorts.cs` (312),
  `Paging/SortDefinition.cs` (37)
- **Non-obvious:** **key columns must be non-nullable, and this is a correctness requirement, not a
  style rule** — `SortDefinition`'s remarks say so: keyset paging emits `col > value` predicates, and
  SQL `NULL` compares to neither side, so a nullable key column silently drops rows from the middle of
  a result set. The fix is pushed into the views (`COALESCE` before use), which is why C2 is a
  dependency of this half even though nothing here reads its DDL. Every sort ends in a unique column so
  that two equal rows can never both be "after" the cursor.

### C20 — Object and finding detail queries
- **Layer:** Infrastructure
- **Owns:** every non-grid question asked about one selected object or one selected finding.
- **Depends on:** C1, C4, C12, C21
- **Implemented by:** `Storage/ObjectQueryService.cs` (1,317)
- **Non-obvious:** the ACL answer is **two-sourced and says which source it used** —
  `AceQuerySource.MaterializedPayload` means AD's applied DACL as captured; `ReconstructedInheritance`
  means C21 rebuilt it, and the result carries a warning that it may not match. That distinction
  travelling with the data, rather than being lost at the boundary, is the best thing in this
  component. Finding evidence is resolved by discriminating on `fact_finding.source_edge_id` /
  `source_path_id` / neither, with the "neither" branch further gated on `context_json` — three
  evidence shapes behind one finding key. `QueryFindingEscalationPathEvidence` joins `dim_asset_tier`
  **unqualified**, so a detail pane shows the *effective* (policy-aware) tier while the rule that
  produced the finding fired on `main.` — deliberate per
  `docs/review/01a-suppression-sidecar-design.md:514`, and worth knowing before anyone "fixes" the
  inconsistency.

  *Sections read for this map:* 1–180, 180–530, 640–830, 860–960, 960–1145, 1195–1310. **Not read
  line-by-line:** 530–640 (`QueryIdentityRaw`, `QueryGroupType`, `QueryOperatingSystem`,
  `EstimateTokenSize`), 1145–1195, 1310–1440 (`ControlEdgeEvidence` / `AceEvidence` records and
  `QueryControlEdgeEvidence`). Public signatures for all of those were enumerated; claims above rest
  only on sections read.

### C21 — Read-time inheritance reconstruction
- **Layer:** Infrastructure
- **Owns:** deriving an object's inherited ACEs from its ancestors' explicit ACEs when no materialized
  payload exists, and reporting whether the ancestor chain was complete.
- **Depends on:** C1, C20
- **Implemented by:** `Security/InheritedAceResolver.cs` (287)
- **Non-obvious:** this is the fallback half of C20's ACL story and exists only because a bundle may
  lack `fact_object_acl_materialized`. It returns an `IsComplete` flag and a warning alongside the ACEs
  — a reconstruction from a partially captured ancestor chain is *wrong*, not merely shorter, and the
  flag is what stops it being presented as authoritative. Constructed at exactly one call site.
  Its sibling `Security/AceAnalysisService.cs` (249) is **not** part of this branch: it aggregates rows
  already fetched and issues no SQL.

### C22 — Grid summary and filter-chip queries
- **Layer:** Infrastructure
- **Owns:** the aggregate counts and lookup maps that sit above a grid: chip counts, distinct filter
  values, SID- and GUID-to-name maps.
- **Depends on:** C1, C4
- **Implemented by:** `Storage/GridSummaryQueryService.cs` (366)
- **Non-obvious:** it exists so the UI layer never writes SQL, which is why it is constructed ad hoc at
  eight view-model sites rather than injected. It carries its own copy of the SQL-identifier allowlist
  regex, independent of C16's. Its counts feed **chips, not tiles** — a scope correction F-01-27
  recorded when it was repaired, and the reason its eight swallow sites are F-01-30's rather than
  F-01-27's.

### C23 — Dashboard queries
- **Layer:** Infrastructure
- **Owns:** the inventory counts, mode probe and pipeline diagnostic behind the dashboard.
- **Depends on:** C1, C4, C9
- **Implemented by:** `Storage/DashboardQueryService.cs` (331)
- **Non-obvious:** **this is the one component in the branch that answers `null` for "could not
  compute" instead of `0`**, and its remarks explain why in the product's terms: the production route
  to a failed count is a degraded run, in which a whole family of tiles fails at once, so zero would
  present a broken bundle as a clean bill of health. That is F-01-27, repaired. `HasSecurityModeTables`
  probes both `sqlite_temp_master` and `sqlite_master` because `v_grid_findings` is a **temp** view
  created per connection by C4 — the probe only ever succeeds on a connection C4 opened, which is a
  real coupling and is documented at the probe. `GetPipelinePhaseDiagnostic` takes its key prefix from
  `DerivedHealthReader` rather than spelling it; it previously spelled `phase_%` against keys written
  as `pipeline_phase_*` and was silent for the life of the feature.

### C24 — Finding severity roll-up from a bundle path
- **Layer:** Infrastructure
- **Owns:** four numbers — critical/high/medium/low finding counts — for a bundle identified by file
  path.
- **Depends on:** C4
- **Implemented by:** `Storage/FindingSummaryService.cs` (44)
- **Non-obvious:** the only read component that takes a **path** and opens its own connection
  (`cacheSizeMB: 0`, with a comment explaining that four aggregate rows do not need a page cache). That
  shape exists because its callers are between bundles, not inside one. It swallows `SqliteException`
  and returns **zeroes**, under the comment *"fact_finding may not exist if this is a Configuration
  Mode DB"* — a claim about a product concept that no longer reaches capture, about a table in
  `SecurityTableDdl`, which C1 executes unconditionally. Same defect class as F-01-27, on a surface
  F-01-27 did not name.

### C25 — Offline directory tree projection
- **Layer:** Infrastructure
- **Owns:** rebuilding an OU/container hierarchy from captured DNs, with per-container object counts, so
  the tree works with no live directory.
- **Depends on:** C1, C4
- **Implemented by:** `Storage/OfflineTreeService.cs` (250)
- **Non-obvious:** the hierarchy is **not stored** — there is no parent-child edge in the schema. It is
  reconstructed in memory by string-parsing DNs, which is why the whole container set is loaded in one
  query and the entire tree assembled before anything is returned. This is the one read component that
  deliberately does not page. It filters `%,CN=Policies,CN=System,%` out of the tree, and pairs with a
  `MaxLeafChildrenPerNode` cap applied by the caller. **Cross-branch:** the Inspect view it feeds is
  scheduled for removal by sequencing item 4 of `00a-product-identity.md`.

### C26 — Live-to-stored object locator
- **Layer:** Infrastructure
- **Owns:** finding the row in `dim_object` that corresponds to an object the user is looking at live.
- **Depends on:** C1
- **Implemented by:** `Storage/AuditObjectLocator.cs` (90)
- **Non-obvious:** it returns a **`MatchBasis`** string — "DN match", "objectGUID match", "SID match" —
  because the three are not equally trustworthy: a DN match after a rename is a different object, a
  GUID match is not. Preference order is GUID, then SID, then DN. It is the only component here that
  interpolates a column name into SQL, guarded by an explicit two-element allowlist. It is also the
  only one that never sets `CommandTimeout`. **Cross-branch:** input comes from H (live verification);
  output is a search string J drills into.

### C27 — Low-signal OU recommendation query
- **Layer:** Infrastructure
- **Owns:** identifying large OUs that produced no findings and hold no Tier-0 objects, as
  evidence-based exclusion candidates for the next run.
- **Depends on:** C1
- **Implemented by:** `Storage/LowSignalOuRecommendationService.cs` (101),
  `Core/Assessment/LowSignalOuRecommendation.cs` (13)
- **Non-obvious:** **it runs at the end of capture, on the write connection**
  (`DirectCaptureRunner.cs:641`), not on a read connection — so unlike everything else here it sees
  `main.dim_asset_tier` with no policy overlay, and its `tier LIKE 'Tier 0%'` guard cannot see a tier
  an operator set by hand. It joins `dim_asset_tier` on `child.sid`, which means the SID-less Tier-0
  objects the write half records under `guid:` keys (`C-storage.md` Naming §4) are invisible to the
  safety check that is supposed to stop you excluding an OU containing them. It also re-checks
  `OuExclusionFilter.IsProtectedContainer` after the query, in C#, because the SQL cannot express it.

### C28 — Read-session write-back
- **Layer:** Infrastructure
- **Owns:** the two things a user can change while reading a sealed bundle: an object's policy tier, and
  a free-text note.
- **Depends on:** C4, C20
- **Implemented by:** `Storage/ObjectQueryService.cs` (`SetAssetTier`, `ClearAssetTier`, `InsertNote` —
  `:906–967`)
- **Non-obvious:** the tier writes are correct and instructive. They go to `dim_asset_tier_policy` in
  the **sidecar**, through a second connection the service must be constructed with, and
  `CreateSidecarCommand` throws a named `InvalidOperationException` if a caller that never tiers tries
  to — a tier is a policy statement, not a fact about the directory, so it must not alter signed
  evidence. `ClearAssetTier` is a plain `DELETE` now precisely because the derived row it overrides
  lives in a different file. **`InsertNote` does none of this**: it writes `dim_object_note` in
  `audit.db` on the main connection, which is read-only. See Would-do-differently §3.

## Naming & taxonomy

### 1. `ObjectQueryService` is neither only about objects nor only a query service

It answers questions about findings, escalation paths, control edges, delegation bundles, the schema
GUID map and Kerberos token size; and three of its members **write** — two to the sidecar, one
attempting `audit.db`. "Object" and "Query" each exclude about a third of what is in the file.

**Rename:** split the name along the split proposed in Would-do-differently §1 — `ObjectDetailQueries`,
`AceQueries`, `FindingEvidenceQueries`, `ReadSessionWriteBack`.

**Why it matters:** the name is why `InsertNote` looks like it belongs. A type called
`ReadSessionWriteBack` would have made "which connection does this write to?" the first question anyone
asked.

### 2. `GridSummaryQueryService` and `DashboardQueryService` are named after screens, not after data

Neither name predicts its contents, and a count that moves from a chip to a tile has to move file.
F-01-27 had to publish a scope correction — *"the finding says the summary services repeat it, implying
they feed tiles. They do not"* — which is a correction only needed because the names invite the
confusion.

**Rename:** `AggregateCountQueries` and `NameLookupQueries`, split by what is asked rather than by where
it is displayed.

**Why it matters:** it is the reason the same defect (F-01-27) was fixed in one of them and not in the
other two (C22, C24) that share its shape.

### 3. `GridId` is a view name

`ContinuationToken.GridId`, `KeysetQueryBuilder.Execute(gridId, ...)`, and `CountRows(viewName, ...)` on
the same type — the last one already uses the honest name. The value is interpolated straight into
`FROM [{gridId}]` and validated as a SQL identifier.

**Rename:** `ViewName` throughout.

**Why it matters:** `GridId` reads like a UI concept, which invites someone to make it one — at which
point the token, whose whole job is to be invalid when the *query* changes, becomes keyed on the wrong
thing.

### 4. `SortRegistry` is not a registry

A registry is something you look things up in. This is 60-odd `public static readonly` fields across two
partial files with **no lookup by `SortId`, no enumeration, and no validation sweep**. Every consumer
names a field at compile time. Yet `ContinuationToken` stores a `SortId` string, and there is nothing
that can turn it back into a `SortDefinition`.

**Rename:** `ApprovedSorts` or `SortCatalog`. Or make it a real registry, keyed by `SortId`, so the
token's `SortId` is resolvable and every definition can be `Validate()`d once at startup rather than on
each query.

**Why it matters:** it is a taxonomy problem with a structural shadow — see Would-do-differently §7.

### 5. `GridFilter.With*` reads immutable and is not

`With` on a record means "copy with this changed." Every `With*` here mutates `_parameters`, invalidates
the cached hash, and returns `this`. The fluent chaining makes it look like the record idiom.

**Rename:** `Add`/`Set`/`Remove`, or make it genuinely immutable.

**Why it matters:** a `GridFilter` handed to two grids is shared state, and the hash it computes is the
identity of an in-flight page cursor.

### 6. `FindingSummaryService` is a static helper with a path argument

It has no state, no constructor, one static method, and takes a file path where every sibling takes a
`SqliteConnection`. Calling it a "Service" puts it in a family it does not belong to.

**Rename:** `FindingSeverityCounts.ForBundle(path)`.

### 7. `OfflineTreeService` is named against a mode that no longer has a counterpart

"Offline" distinguished it from a live LDAP tree. Live browsing as a destination is scheduled for
removal, and the audit workflow has no online tree to contrast with.

**Rename:** `CapturedTreeProjection` — and note the type is a projection, not a service, since nothing
about it persists between calls.

## Would-do-differently

### 1. `ObjectQueryService` is four components sharing a file

1,317 lines, ~30 public members, spanning object identity, group membership, ACL retrieval, finding
evidence, the schema GUID map, asset tiers and notes. It has two connections, two command factories, a
public mutable `Warnings` list, and eleven nested record types. It is constructed ad hoc —
`new ObjectQueryService(_connection)` — at call sites in view models, once per operation.

**Ideal:** the C20/C21/C28 split above, as separate types with separate dependencies. The `AceQueries`
type needs `InheritedAceResolver` and the materialized codec; `ObjectDetailQueries` needs neither;
`ReadSessionWriteBack` needs the sidecar connection and *should not compile* without it. Today the
sidecar dependency is an optional constructor parameter defaulting to `null`, so "did the caller pass a
sidecar" is a runtime question answered by an exception message.

### 2. The swallow population on this branch, and a warning channel nobody listens to

`ObjectQueryService` has **19** `catch (SqliteException)` blocks. **Two** of them record a
`QueryWarning`. `git grep "\.Warnings"` across `src` and `tests` returns three hits: the two
`Warnings.Add` calls, and `MainViewModel.Dashboard.cs:82` reading **`DashboardQueryService`**'s list.
**`ObjectQueryService.Warnings` is populated and never read by anything.**

**Addition to `docs/review/01-infrastructure-storage.md`, F-01-30.** The finding enumerates
`ObjectQueryService`'s sites (17 or 18 depending on the amendment) and correctly notes they disagree
about what a swallowed failure means. It does not record that the type already grew a reporting channel
for exactly this and wired it to nothing — which changes the repair from "decide a meaning per site" to
"decide a meaning per site, and give the channel a reader or delete it." Two of nineteen is worse than
zero of nineteen, because it looks like the problem was addressed.

### 3. Saving a note writes to a read-only database, and the UI reports success

`InsertNote` issues an `INSERT INTO dim_object_note` on the main connection. `dim_object_note` is in
`audit.db` (`DerivedStoreSchema.cs:300`), and every path that binds this connection comes from
`DatabaseConnectionFactory.OpenReadOnly`. The caller, `ObjectDetailPanelViewModel.SaveNote`
(`:336–353`), wraps it in `catch (Exception)` → `Debug.WriteLine`, then clears the input box and
refreshes the notes list. **The user types a note, the box empties, and nothing appears.**

**New finding; addition to `docs/review/01-infrastructure-storage.md`.** It is F-01-30 in kind — a
swallowed exception — but not in consequence: this is a whole feature that cannot work, not a count that
might be wrong. `docs/DATA-MODEL.md:52` lists `dim_object_note` as *"User-added notes on objects"*
without recording that user additions cannot reach it.

**Ideal:** notes are user-editable state, which is precisely what the sidecar exists for. Move
`dim_object_note` into `suppressions.db` beside `dim_asset_tier_policy`, route it through
`CreateSidecarCommand`, and let the missing-sidecar case throw the named exception that path already
has. The correct design is ten feet away in the same file.

### 4. F-01-27's answer was applied to one of the three surfaces that have its shape

`DashboardQueryService` now returns `int?` and renders unknown. Still returning a confident zero for a
failed query: `KeysetQueryBuilder.CountRows` (documented as *"Row count, or 0 if the query fails"*), and
`FindingSummaryService.CountBySeverity` (returns `SeverityCounts(0,0,0,0)`). The latter feeds
`MainViewModel.Audit.cs:219` and `MainViewModel.GridBinding.cs:225` — post-run and post-load severity
summaries, which is the surface most likely to be read as "the forest is clean."

**Ideal:** the same answer, three times. `int?` and `SeverityCounts?`, with the existing `DataLoadState`
convention at the render site. The convention is already stated in `GridViewModelBase.cs:12-16` and
honoured by eight view models.

The stale comment goes with it: *"fact_finding may not exist if this is a Configuration Mode DB"* is
false twice over — configuration mode is not reachable, and `fact_finding` is in `SecurityTableDdl`,
which C1 executes unconditionally on every database this build writes.

### 5. The read path still probes for tables, which decision 0002 exists to prevent

`ObjectQueryService.TableExists` (`:801`) and `LowSignalOuRecommendationService.TableExists` (`:104`) are
two independent copies of the same `sqlite_master` probe. `QueryTransitiveGroupSids` carries *"Table may
not exist in older databases"* — a legacy-shape claim decision 0001 forbids. C9's `RunCoverageReader`
comments already say the opposite in four places: base DDL runs unconditionally, so an absent table
means a broken read, not an old bundle.

The one probe that is legitimate is `DashboardQueryService.HasSecurityModeTables`, and only because
`v_grid_findings` is a **temp** view created per connection by C4 — its existence genuinely is a
property of the handle, not the file. That one should be renamed to say so.

**Ideal:** health is one verdict, read once, per decision 0002. `ObjectQueryService`'s
`fact_object_acl_materialized` probe is the interesting case — that table's presence is a real
capture-shape variable, so it should be a recorded fact in `dim_database_metadata` rather than
rediscovered per object selection.

### 6. Paging is a genuine discipline with three exits, and the exits are undocumented

C16–C19 are a serious answer to "read a 17 GB database without loading it." Then: `OfflineTreeService`
loads every container in the forest and builds the whole tree eagerly; `QueryObjectsAccessibleBy` caps
at `LIMIT 500` and returns a `List` with no indication it truncated; `GridSummaryQueryService`'s chip
counts are unbounded aggregates.

Two of the three are defensible — a container set is small, chips need totals.
`QueryObjectsAccessibleBy` is not: "Who has access?" silently answering 500 of N is the same defect as
F-01-27 in a different currency, and the 501st row is as likely to matter as the first.

**Ideal:** anything that truncates says so in its return type. A `Truncated` flag costs one bool and
removes a class of wrong answer.

### 7. The cursor names a sort it cannot resolve

`ContinuationToken.SortId` exists so a token can be rejected when the sort changed. But nothing can map
a `SortId` back to a `SortDefinition` (Naming §4), so the token is only ever checked against a
definition the caller already had. The `SortId` is therefore load-bearing for *invalidation* and useless
for *reconstruction* — which means a page cursor cannot survive anything that does not also carry the
sort object, and paging state cannot be persisted or passed across a process boundary.

Similarly, `SortDefinition.Validate()` is called per query inside `Execute`, on immutable static
definitions that cannot change between calls. Its two invariants — non-empty keys, matching direction
count — are startup facts.

**Ideal:** a real registry keyed by `SortId`, validated once at startup (a test would do), and a token
that resolves its own sort. That also makes the non-nullable-key-columns rule enforceable rather than
documented: a startup sweep could check every `SortDefinition`'s key columns against the view's schema,
which is currently a comment in `SortDefinition`'s remarks and nothing else.

### 8. This was right, keep it: keyset paging with a self-invalidating cursor

Offset paging over a 17 GB SQLite file degrades quadratically and, worse, silently changes its answer
when the underlying set changes. This branch chose keyset paging, made every sort end in a unique
tie-breaker so a cursor is never ambiguous, fetched `n+1` rows so "is there more" costs nothing, and
hashed the normalised filter into the cursor so that a filter change is *detected* rather than producing
a plausible-looking but wrong page.

The detail that makes it hold together is the one that looks like a nuisance: **key columns must be
non-nullable**, pushed into the view definitions as `COALESCE`. That is not fussiness — a `NULL` key
column makes `col > value` false for rows that should be after the cursor, and those rows vanish from
the middle of the result set with no error anywhere. The rule is written down at the point of
definition, which is the only reason it would survive a rebuild.

Keep the design, keep the `n+1` trick, keep the filter hash, keep the identifier allowlist in
`KeysetQueryBuilder` and the explicit security contract on `WithExists` — and if the rest of this branch
is restructured, keep `SortDefinition`'s remarks verbatim, because they encode a failure mode that
leaves no evidence when violated.
