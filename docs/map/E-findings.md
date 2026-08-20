# E — Findings & Rules (part 1: the findings run)

**Owns:** everything between "every fact, stated and derived, is in `audit.db`" and "a persisted
`fact_finding` row with a severity, a coverage verdict, and a state a human can change." It begins
where D's derived phases end and stops at the `IRuleEvaluator` contract, which the second half
([`E-rules.md`](E-rules.md)) picks up.

**Split note:** this branch is roughly 11,300 lines and is split at `IRuleEvaluator.Evaluate`. This
file covers the run, the verdict, and the finding's later life (E1–E15). `E-rules.md` covers the ten
evaluators, `RuleEvaluatorHelpers`, the catalogues and `rules.yaml` (E16 onward). Numbering is
continuous across both files, so a reference to `E4` or `E19` is unambiguous without naming which
half it lives in.

## The flow

1. **`DirectCaptureRunner` calls `pipeline.ExecuteFindingsAsync`** (`:575`), after D's nine derived
   phases and after `PersistControlEdgeCoverage` / `PersistEscalationPathCoverage` have written the
   derived `fact_coverage` rows. The interleaving is deliberate — findings read coverage, so coverage
   must be final.
2. **`ExecuteFindingsAsync`** (`DerivedAnalysisPipeline.cs:115`) runs exactly two phases through the
   same `RunPhase`/`RunPhaseAsync` fault isolation D1 uses, then writes its own `findings_health`
   metadata row — `Complete`, or `Degraded:` plus the failed phase names. It is a second pipeline
   sharing D1's class.
3. **`GenerateFindingsAsync`** (`:418`) constructs a `FindingsService` over the write connection with
   **`FindingsPolicy.Empty`, hardcoded**, and calls `GenerateAllFindingsAsync`.
4. **`GetRunCoverageState()`** reads `fact_coverage`, unions the domains it finds with domains
   discovered from `dim_object`, and returns per-module completeness. A domain present in `dim_object`
   but absent from `fact_coverage` counts as incomplete, not as absent.
5. **`BuildPrivilegedSidProvenance()`** reads `fact_group_membership_closure` (D6's output) filtered by
   `PrivilegedGroupCatalog`, producing both a privileged-SID set and a member → privileged-groups map.
   If the closure table is missing it degrades to the well-known exact SIDs alone.
6. **`ClearFindingsForRun(runId)`** deletes `fact_finding` rows for the run id. The run id was generated
   by `Guid.NewGuid()` four lines earlier, so this always deletes zero rows.
7. **Evaluators fan out in parallel.** If the database is file-backed, `Parallel.ForEach` gives each of
   the ten evaluators its own `DatabaseConnectionFactory.OpenReadOnly` connection (WAL permits
   concurrent readers) and each evaluates its rule ids in ordinal order. Rules disabled in
   `BuiltInRules` are skipped. A throwing rule is recorded as an error string and the run continues.
   In-memory databases fall back to a sequential pass on the shared connection.
8. **`EnrichFindingsWithDisplayNames`** rewrites each non-path finding's `ContextJson` to add
   `subject_name` / `target_name`, resolving through `WellKnownSidCatalog` then `dim_object`. Path
   findings already carry names and are skipped.
9. **`EnrichFindingsWithPrivilegeProvenance`** injects `subject_privileged_via` into `ContextJson` for
   any non-path finding whose subject has a provenance entry.
10. **`StampCoverageOnFindings`** maps each finding's rule id through `RuleCoverageRequirements` to a
    module list, resolves the finding's domain from `dim_object` / `dim_principal` / the target itself,
    and stamps `CoverageComplete` + `CoverageReason`. Path findings keep their per-row coverage from
    `fact_escalation_path` and only have a reason filled in.
11. **`FindingsPolicyEvaluator.Apply`** runs — and returns immediately, because the policy is always
    `Empty` (step 3).
12. **`ApplySuppressions`** runs — and returns 0, because `SetSuppressions` has no callers anywhere in
    the repository, so `_suppressions` is always empty.
13. **Sort by `finding_key` ordinally**, then one transaction: `INSERT OR IGNORE` every finding into
    `fact_finding`, insert one `dim_run` row, commit. Rollback and rethrow on any failure — findings and
    the run manifest are written together or not at all.
14. **`BackfillFindingPrincipals`** (`DerivedAnalysisPipeline.cs:512`) finds every
    `fact_finding.subject_sid` with no `dim_principal` row, resolves through the well-known catalogue
    then `dim_object`, and falls back to the raw SID. This writes a B table but belongs here: findings
    invented these SIDs.
15. **Later, on demand:** the UI opens read-only connections and constructs `FindingsService` purely to
    call `GetFindings`, `GetSummary`, `GetRunCoverageState` or `GenerateActionReport`. Suppression at
    this point runs through an entirely different mechanism — `SuppressionService` over the
    bundle-local `suppressions.db` sidecar, keyed by exact `finding_key`.

The shape of the branch is set by steps 11 and 12. Two substantial subsystems — 900 lines of policy,
270 of typed suppression — sit on the critical path and are unreachable, while the suppression that
users actually experience is a different mechanism bolted on at read time.

## Components

### E1 — Findings pipeline phase
- **Layer:** Infrastructure
- **Owns:** the ordered pair of findings phases, their fault isolation, and the run's verdict on its
  own findings output.
- **Depends on:** D1, D2, E2, E13
- **Implemented by:** `Storage/DerivedAnalysisPipeline.cs` — `ExecuteFindingsAsync` (`:115–133`),
  `GenerateFindingsAsync` (`:418–423`), `BackfillFindingPrincipalsPhase` const (`:23`)
- **Non-obvious:** this is the half of D1 that belongs to E, and the reason D1 carries a
  would-do-differently item about the shared type. It has its own health key (`findings_health`)
  distinct from D's `derived_health`, so a bundle can be `derived_health=Complete` and
  `findings_health=Degraded` simultaneously. **Cross-branch input:** `DirectCaptureRunner` (B) and
  `ExistingCaptureAnalysisService` (D20) are the only two callers. `GenerateFindingsAsync` is where the
  policy is pinned to `Empty` — a three-line method that disables E8 entirely.

### E2 — Findings run orchestration
- **Layer:** Infrastructure
- **Owns:** the evaluator registry, the parallel fan-out, the fixed order of enrichment / stamping /
  policy / suppression, and the run's result summary.
- **Depends on:** C4, D2, E3, E4, E5, E6, E8, E9, E15, E16 (the evaluator set)
- **Implemented by:** `Findings/FindingsService.cs` (453)
- **Non-obvious:** the parallel path and the sequential path are **not equivalent**. The parallel branch
  iterates `_categoryEvaluators` and skips rules where `BuiltInRules.ById[id].EnabledByDefault` is
  false; the sequential branch iterates `_ruleToEvaluator.Keys` and applies **no such check**, so a
  disabled rule runs against an in-memory database and does not run against a file-backed one. Since
  tests run in-memory and production runs file-backed, the disabled-rule gate is exercised in exactly
  the configuration where it is not tested. `rulesTriggered` also counts differently between the two
  branches. `GenerateAllFindingsAsync` returns `Task.FromResult` — it is synchronous throughout despite
  the signature.

### E3 — Privileged-principal set & provenance
- **Layer:** Infrastructure
- **Owns:** which SIDs count as privileged for rule purposes, and which privileged groups each one
  inherits that from.
- **Depends on:** D6 (`fact_group_membership_closure`), B (`PrivilegedGroupCatalog`, `dim_principal`)
- **Implemented by:** `Findings/FindingsService.cs` — `BuildPrivilegedSidProvenance` (`:398–450`),
  `BuildPrivilegedSidSet` (`:386`)
- **Non-obvious:** this is the single most consequential input to the whole branch — it is handed to
  every evaluator via `RuleEvaluationContext` — and it degrades **silently**. If
  `fact_group_membership_closure` is missing (D6's phase failed, and D1 continues past a failed phase),
  the set collapses to the hardcoded well-known SIDs and every rule that asks "is this principal
  privileged?" quietly answers "no" for every real-world admin. Nothing in `FindingsRunResult` records
  that this happened. `BuildPrivilegedSidSet` exists only as a one-line adapter for E2's dead debug
  helper.

### E4 — Coverage verdict on a finding
- **Layer:** Infrastructure
- **Owns:** whether a finding is trustworthy, per domain and per module, and the human-readable reason
  when it is not.
- **Depends on:** B18 (`fact_coverage`), C1, D17
- **Implemented by:** `Findings/FindingsService.Coverage.cs` (228),
  `Coverage/CoverageEnforcementService.cs` (294), `RuleCoverageRequirements` in
  `Findings/FindingsService.cs` (`:29–92`)
- **Non-obvious:** **this claims `CoverageEnforcementService` for E**, against the alternative of K. The
  argument: its four call sites all reduce to one question — "is this conclusion safe to state?" —
  which is E's question, not a cross-cutting utility. `EscalationPathService` (D) asking it does not
  make it D's any more than D asking `dim_object` makes `dim_object` D's. It is constructed fresh per
  call in all four sites and holds no state, so nothing is lost.

  `RuleCoverageRequirements` is a 64-entry hand-maintained dictionary mapping SEC-* ids to module
  lists. It lives in `FindingsService.cs` and is the *only* thing that knows a rule's data
  dependencies; the evaluators themselves do not declare them. A new rule added without an entry here
  falls through to `GetCoverageRequirements`'s heuristic default (`[Objects]`), which will call it
  complete on a bundle where its actual inputs were never captured. That is a silent wrong answer, not
  a visible gap.

  The domain-discovery query filters `RootDNSServers` out of `dim_object` with three separate
  `NOT LIKE` clauses — a workaround for a partition that would otherwise appear as a permanently
  uncovered domain.

### E5 — Finding enrichment
- **Layer:** Infrastructure
- **Owns:** the display names and privilege provenance injected into a finding's `ContextJson` before
  persistence.
- **Depends on:** B (`dim_object`, `dim_principal`, `WellKnownSidCatalog`), E3
- **Implemented by:** `Findings/FindingsService.Enrichment.cs` (347)
- **Non-obvious:** this exists to stop I and J round-tripping every SID and GUID through
  `PrincipalResolutionService` at render time — a stated performance decision, and a sound one. Its cost
  is that `ContextJson` is a schemaless blob with an informally reserved key namespace (`subject_name`,
  `target_name`, `subject_privileged_via`), enforced only by "reserved keys already present are not
  overwritten." `EnrichmentJsonOptions` carries a `DefaultJsonTypeInfoResolver` purely because passing
  custom options to `JsonNode.ToJsonString` otherwise fails under trimming — a comment records this, and
  it is worth keeping.

### E6 — Finding persistence & run manifest
- **Layer:** Infrastructure
- **Owns:** the `fact_finding` row shape, the `dim_run` manifest, and the atomicity between them.
- **Depends on:** C1 (schema), E15
- **Implemented by:** `Findings/FindingsService.Persistence.cs` (216), `Core/Findings/RunRecord.cs` (50)
- **Non-obvious:** the transaction wrapping findings and `dim_run` together is deliberate and correct —
  it is what makes "a run id with findings but no manifest" unrepresentable. But roughly a third of this
  file is dead: `CreateEdgeFindingV2` (`:13`) and `CreateDelegationFindingV2` (`:42`) have **zero callers
  repo-wide**; `TruncatePathDetail` (`:68`) and `GetDomainObjectGuid` (`:77`) are byte-identical
  duplicates of `RuleEvaluatorHelpers:748` and `:757`, and only the `RuleEvaluatorHelpers` copies are
  used; `GetFirstDomainObjectGuid` (`:91`) has no callers. The evaluators construct `FindingV2`
  themselves, so the "factory" role this file's header claims was superseded and never removed.

  `CreateRunRecord` hardcodes `AssessmentMode = "Security"` and `Scope = ScopeId = "(auto)"`,
  `ScopeKind = "domain"` — residue of scoped capture, removed 2026-08-02. The columns survive because C1
  declares them; nothing reads these three values.

### E7 — Finding read-back
- **Layer:** Infrastructure
- **Owns:** the query surface over `fact_finding` for everything downstream of the run.
- **Depends on:** C4, E6, E15
- **Implemented by:** `Findings/FindingsService.Queries.cs` (294)
- **Non-obvious:** `GetFindings(runId, minSeverity)` filters severity **in C#, after** `SELECT`ing every
  row for the run — the `WHERE` clause has no severity predicate. On a forest with hundreds of thousands
  of findings, asking for Critical only reads and materialises all of them. `ClearFindingsForRun`
  (`:192`) is called once, with a GUID created moments earlier, so it can never match a row; the "fresh
  run each time" comment at its call site describes an intention the code does not implement (nothing
  deletes prior runs' findings — `fact_finding` accumulates across re-analysis, keyed by run id).
  **Cross-branch output:** J's `FindingsGridViewModel` and I's report generators are the consumers.

### E8 — Findings policy
- **Layer:** Infrastructure (evaluator, loader, audit log) / Core (policy model)
- **Owns:** operator-authored allow-listing, severity overrides and hop limits over a finding set, plus
  the audit trail of what it changed.
- **Depends on:** E15, B (`dim_principal`), D (`fact_escalation_path` hop counts)
- **Implemented by:** `Findings/FindingsPolicyEvaluator.cs` (482), `Findings/FindingsPolicyLoader.cs`
  (245), `Findings/FindingsPolicyAuditLog.cs` (84), `Core/Findings/` — `FindingsPolicy.cs` (28),
  `IFindingsPolicy.cs` (22), `IFindingsPolicyLoader.cs` (15), `PolicyFileDtos.cs` (40),
  `PolicyLoadResult.cs` (18), `PolicyEvaluationResult.cs` (22), `PolicyDiagnostics.cs` (45),
  `AllowedPrincipalEntry.cs` (47), `SeverityOverrideEntry.cs` (14), `TargetScope.cs` (18)
- **Non-obvious:** **this entire subsystem — roughly 1,080 lines — never executes.**
  `GenerateAllFindingsAsync` is called from exactly one place (`DerivedAnalysisPipeline.cs:422`), and two
  lines above it the policy is pinned to `FindingsPolicy.Empty`. `FindingsPolicyEvaluator.Apply`
  early-returns on `policy.IsEmpty` before touching a finding. `FindingsPolicyLoader` is constructed at
  exactly one site, `MainViewModel.Dashboard.cs:92`, where it loads a policy file **only to display a
  summary badge on the dashboard** — the loaded policy is never handed to a `FindingsService`.
  `policyLoaded` defaults to `false` and no call site passes `true`, so
  `FindingsRunResult.PolicyDiagnostics` is always null.

  The design is not the problem — the design is good. `EvaluateTargetScope` returns a three-valued
  result distinguishing `NoMatch` from `Unresolvable` so that "we could not tell" is not silently
  treated as "it did not match", and the hop-limit check fails **open** (retains the finding) when a
  path id is not found. Both are the right defaults. They just never run. The tests
  (`FindingsPolicyEvaluatorTests`, `FindingsPolicyLoaderTests`) construct the evaluator directly and
  pass, which is why this has stayed green.

### E9 — Typed suppression matching
- **Layer:** Infrastructure (matcher) / Core (entry model)
- **Owns:** pattern-based suppression of findings by trustee, account, edge or pair identity, applied at
  generation time.
- **Depends on:** E15
- **Implemented by:** `Findings/SuppressionMatcher.cs` (167), `Findings/FindingsService.Suppression.cs`
  (34), `Core/Findings/SuppressionEntry.cs` (102)
- **Non-obvious:** **also entirely dead.** `FindingsService.SetSuppressions` is `public`, is documented
  as "must be called before `GenerateAllFindingsAsync`", and has **zero callers in any tracked file** —
  src, tests, tools. `_suppressions` therefore holds `Array.Empty<SuppressionEntry>()` on every run,
  `ApplySuppressions` early-returns 0, and `fact_finding.suppressed` is `0` for every row ever written.
  `SuppressionMatcher` is exercised only by its own ten unit tests, which call it directly.

  This is a genuinely different concept from E10, not a duplicate implementation: `SuppressionEntry`
  matches **patterns** (this trustee, on these rules, within this OU subtree) and survives re-capture
  because it does not name a finding; `SuppressionRecord` matches an **exact `finding_key`** and does
  not. The pattern one is the better design and is the one that does not run. `SuppressionScope`'s doc
  comments enumerate which SEC-* rules each scope was intended for — the design intent is recorded in
  full, on code that has never executed.

### E10 — Suppression state (the live one)
- **Layer:** Infrastructure
- **Owns:** what "accepted" means for a specific finding: who accepted it, why, when it expires, and
  whether it has been revoked.
- **Depends on:** C5 (the sidecar and its `dim_suppression` DDL), C4 (`OpenSuppressionWrite`)
- **Implemented by:** `Findings/SuppressionService.cs` (177), `Core/Findings/SuppressionRecord.cs` (45),
  `Core/Services/ISuppressionService.cs`
- **Non-obvious:** **boundary against C5:** C5 owns the sidecar as *storage* — the file, the `ATTACH`,
  the DDL. E10 owns the *semantics* — that `active=1` plus a future-or-null `expires_utc` means
  accepted, that `Unsuppress` revokes rather than deletes (setting `active=0` and stamping
  `revoked_utc`, preserving the audit trail), and that `ImportAcceptance` differs from `Suppress` only
  in carrying `source_run_id` provenance. F keeps whether a sealed run may accept new suppressions.

  The reason this is a sidecar rather than a column on `fact_finding` is recorded in the type's own
  remarks and in `docs/review/01a-suppression-sidecar-design.md`: accepting a risk is a user edit, and
  user edits to `audit.db` invalidate the signature taken at capture. That is a good decision, well
  documented at the point of use.

  Expiry is **not enforced here** — `GetAllActive` filters on `active = 1` only and ignores
  `expires_utc` entirely. Whether an expired acceptance resurfaces depends on whichever consumer
  remembers to check, which is a J concern this component silently delegates.

### E11 — Acceptance import
- **Layer:** Infrastructure
- **Owns:** carrying accepted-risk decisions forward from a previous run's bundle into the current one.
- **Depends on:** E10, E15, C5
- **Implemented by:** `Findings/AcceptanceImportService.cs` (273), `Core/Findings/AcceptanceImportResult.cs`
  (175)
- **Non-obvious:** this is the component that makes E10's exact-`finding_key` matching survivable across
  runs at all — without it, every re-capture would discard every acceptance. It is the workaround for E9
  being dead. **Cross-branch output:** driven from J (`ImportAcceptancesViewModel`,
  `FindingsGridViewModel`); this is a user-initiated action, not part of the run.

### E12 — Action report
- **Layer:** Infrastructure (grouper, priority) / Core (model, hints)
- **Owns:** collapsing many findings into one remediation action per root cause, and ranking those
  actions.
- **Depends on:** E7, E15, D11 (`dim_asset_tier`), B (`WellKnownSidCatalog`)
- **Implemented by:** `Findings/ActionGrouper.cs` (305), `Findings/ActionPriorityCalculator.cs` (137),
  `Findings/FindingsService.ActionReport.cs` (55), `Core/Findings/ActionReport.cs` (111),
  `Core/Findings/ActionIdentity.cs` (106), `Core/Findings/RemediationHintCatalog.cs` (109)
- **Non-obvious:** **this is E's most arguable claim.** Nothing here is persisted.
  `GenerateActionReport` is called from exactly one place — `MainViewModel.Home.cs:107` — on a read-only
  connection, on demand, and the result is thrown away when the view closes. By the prior that "E ends
  at a persisted `fact_finding` row plus its severity and priority" this belongs to I, because the
  priority it computes never reaches a row. It is claimed for E on the grounds that grouping findings by
  root cause and scoring them is a statement about what the findings *mean*, and I owning a scoring
  policy would mean two branches could disagree about which finding matters most. The counter-argument
  is real and the alternative placement is legitimate.

  The `IsTier0Action` comments in `EscalationPathRuleEvaluator` (`:79`, `:252`) assert agreement with
  this calculator. They are comments only — no call, no shared code, no test. Two independent Tier-0
  definitions maintained by assertion.

  The severity-then-priority sort in `FindingsService.ActionReport.cs:40` carries an unusually good
  comment explaining *why* priority alone is unsafe as a sort key: the 5x Tier-0 multiplier lets a
  Tier-0 Medium (1250) outrank a Critical affecting Everyone across nine findings (1080). That reasoning
  would have been invisible from the code.

  `ActionPriorityCalculator.LoadTier0Objects` joins `dim_object o ON o.sid = t.sid`, so an object with
  no SID — every OU and every GPO — can never be recognised as a Tier-0 *object*, only as a Tier-0
  principal. Given that `IsObjectCentricRule` routes GPO and LAPS findings to object identity,
  GPO-scoped actions cannot receive the Tier-0 boost.

### E13 — Finding principal backfill
- **Layer:** Infrastructure
- **Owns:** ensuring every SID a finding names has a `dim_principal` row to join to.
- **Depends on:** E6, B (`dim_object`, `dim_principal`, `LdapAttributeHelper`)
- **Implemented by:** `Storage/DerivedAnalysisPipeline.cs` — `BackfillFindingPrincipals` (`:512`)
- **Non-obvious:** per the settled ruling, this is E's although it writes a B table, mirroring D6's
  `EnsureExpansionGroupsResolved`. The two are near-identical in shape and sit in the same file,
  differing only in which query supplies the missing SIDs. Its final fallback inserts the raw SID string
  as the display name, so an unresolvable SID becomes a `dim_principal` row rather than a dangling
  reference — which is what makes J's joins safe, at the cost of `dim_principal` containing rows the
  directory never stated.

### E14 — Run diff
- **Layer:** Infrastructure (service) / Core (result)
- **Owns:** which findings are new, fixed or unchanged between two runs.
- **Depends on:** E7, E15
- **Implemented by:** `Findings/RunDiffService.cs` (162), `Core/Findings/RunDiffResult.cs` (79),
  `Core/Services/IRunDiffService.cs`
- **Non-obvious:** **no production consumer.** `git grep` for `IRunDiffService` and `RunDiffResult`
  across `src` and `tests` returns the interface, the implementation, the result record, and
  `RunDiffServiceTests` — no registration, no injection, no call site. It is a complete, tested G-branch
  (Compare) component with no G to attach to. It also carries a fourth copy of the `fact_finding`
  row-reading SQL (`ReadFindings`, `:133`), independent of E6's `ReadFinding`.

### E15 — Finding record contract
- **Layer:** Core
- **Owns:** what a finding *is* — its identity, severity, subject, target, provenance and state.
- **Depends on:** —
- **Implemented by:** `Core/Findings/FindingV2.cs` (83), `Core/Findings/Severity.cs` (22),
  `Core/Findings/FindingsRunResult.cs` (60), `Core/Findings/RuleCategory.cs` (37)
- **Non-obvious:** `FindingKey` is the deduplication identity and the join key for E10's acceptances,
  and it is composed by string concatenation inside each evaluator
  (`$"{ruleId}|{subjectSid}|{targetId}"` in the dead factories; each evaluator does its own). There is
  no single type that owns the format, which is why `PathFindingKeyStabilityTests` exists — a test
  guarding a convention that no code enforces. `SourceEdgeId` and `SourcePathId` being nullable and
  mutually exclusive is the mechanism by which E4 knows a finding already carries per-row coverage;
  nothing declares that invariant.

## Naming & taxonomy

| Current | Proposed | Why it matters |
|---|---|---|
| `FindingsService` | `FindingsRun` (generation) + `FindingsQuery` (read-back) | The name hides that this is two types. Seven of its nine construction sites build it with `FindingsPolicy.Empty` purely to call a query method, paying for the ten-evaluator registry construction to run one `SELECT`. The name gives no signal that most callers want only a third of it. |
| `FindingV2` | `Finding` | The `V2` names a migration from a `V1` that no longer exists (`LegacyFindingsPurgeProofTests` guards its absence). A version suffix on the central domain type of a branch invites the reader to look for the other one. |
| `SuppressionEntry` vs `SuppressionRecord` | `SuppressionRule` vs `FindingAcceptance` | These two names are near-synonyms for genuinely unrelated concepts — a reusable match pattern versus a stamped decision about one specific finding — and they live in the same namespace. Almost every misreading of the suppression story starts here. |
| `SuppressionService` | `AcceptanceStore` | It manages E10's sidecar records; it has nothing to do with E9's `SuppressionMatcher`. The shared prefix implies a relationship that does not exist. |
| `FindingsPolicyEvaluator` | `PolicyFilter` | "Evaluator" collides head-on with `IRuleEvaluator`, the branch's other and much more central abstraction. One produces findings; this one filters them. |
| `ActionPriorityCalculator.EnhancePriority` | `ApplyTier0Boost` | It does exactly one thing — multiply by five when Tier-0 is involved — and the name promises a general priority model. The XML doc's "and other contextual factors" describes no code. |
| `RuleCoverageRequirements` | `RuleDataDependencies` | It is not about coverage; it is the declaration of which capture modules each rule reads. Coverage is what happens when a dependency is unmet. The current name buries the branch's only dependency declaration inside its consequence. |
| `RunDiffService` | `FindingsDelta` | Minor, but "run diff" reads as a run-lifecycle concept (F) when it compares finding sets. |
| `GetTopNoisyRules` | `GetFindingCountsByRule` | It computes counts descending; "noisy" is a judgement the method does not make. |

## Would-do-differently

**Rules should declare their own data dependencies.** The single most consequential structural problem
in this branch is that `RuleCoverageRequirements` — a 64-entry dictionary in `FindingsService.cs` — is
the only place a rule's inputs are written down, and it is maintained by hand, separately from the rule.
A rule added without an entry gets `[Objects]` from a heuristic default and is stamped coverage-complete
on a bundle where its real inputs were never captured. That is not a missing feature, it is a wrong
answer presented confidently. `IRuleEvaluator` should carry `IReadOnlyList<string> RequiredModules` per
rule id, and E4 should read it from there. The dictionary is then a test fixture, not a runtime
dependency.

**Two dead subsystems on the critical path is a process failure, not a code failure.** E8 (~1,080 lines)
and E9 (~300 lines) are both well-designed, both fully unit-tested, and both unreachable — E8 because
`GenerateFindingsAsync` hardcodes `FindingsPolicy.Empty`, E9 because `SetSuppressions` has no caller.
Neither has an `[Obsolete]`, a TODO, or a failing test. The tests pass *because* they construct the
components directly and never assert that production reaches them. In a rebuild, the guard is a wiring
test: for each subsystem with a public entry point, assert that some production path invokes it. That
test would have failed on the first commit of both. The deeper lesson is that unit tests measure whether
a component works, not whether anything calls it, and this branch has 1,400 lines of proof of that
distinction.

**Suppression was designed twice and shipped the weaker half.** E9 matches patterns and survives
re-capture by construction; E10 matches an exact `finding_key` and needs E11 (273 lines) to survive
re-capture at all. The pattern design is better and is the one that does not run. A rebuild should have
one suppression concept, pattern-based, applied at generation time and persisted to the sidecar — which
collapses E9, E10 and E11 into one component and deletes the import path entirely.

**The parallel and sequential evaluation paths should not be two code paths.** The disabled-rule check
exists in one and not the other, and the branch is selected by whether the database is in memory —
which is precisely the axis that separates tests from production. Whatever the rebuild does about
parallelism, both paths must run the same rule-selection logic, or there must be one path. The current
arrangement means the production configuration is the untested one.

**`ContextJson` should be typed.** A schemaless JSON blob with an informally reserved key namespace is
how E5 hands names to I and J, how E12 recovers edge identity (`ActionGrouper.TryExtractEdgeIdentity`
parses it and swallows all exceptions), and how privilege provenance travels. Three components read keys
that no type declares. A discriminated evidence record per finding kind would cost more up front and
remove an entire class of silent failure — `TryExtractEdgeIdentity` returning false on a malformed blob
currently downgrades an edge action to a principal action with no diagnostic.

**Findings should not accumulate silently across runs.** `ClearFindingsForRun` is called with a fresh
GUID and deletes nothing; the comment above it says "fresh run each time." `fact_finding` in fact grows
without bound across re-analysis. Either the retention decision is explicit and F owns it, or the clear
is real — the current state is a comment describing behaviour that does not exist.

**This was right, keep it: the coverage verdict is carried on the finding, not inferred at render
time.** Every finding carries `CoverageComplete` and a `CoverageReason` written at generation, from the
coverage state as it stood when the rule ran. Nothing downstream has to re-derive whether a conclusion
was safe, and nothing can quietly disagree. It is the same instinct that made D2's `Unrecorded` weaker
than `Degraded` — a finding from an incompletely-captured domain says so, in its own row, in words. The
mechanism that *produces* the verdict has the flaw described above; the decision to attach the verdict
to the fact rather than compute it on demand is the right one and should survive a rebuild unchanged.

**Also right: findings and their run manifest commit together.** The transaction in
`GenerateAllFindingsAsync` makes "findings with no run row" unrepresentable, which is what allows every
downstream join to assume a `dim_run` exists.

## Corrections to existing documents

Recorded so the corrections are traceable rather than silent.

| Document | Claim | Correction |
|---|---|---|
| `tests/SecureAD.UI.Tests/Views/CoverageVisibilityBindingGuardTests.cs:17` | Names `FindingEvidenceMatrix` as an example of a type "with no enforcing consumer". | Stale. `tests/SecureAD.Core.Tests/Findings/FindingEvidenceMatrixTests.cs` asserts rule-id parity against `BuiltInRules` in four tests. The type does have an enforcing consumer. |
| `src/SecureAD.Infrastructure/Findings/FindingsService.Persistence.cs` file header | Claims the file owns "Finding Factories". | Both factory methods (`CreateEdgeFindingV2`, `CreateDelegationFindingV2`) have zero callers; the evaluators construct `FindingV2` directly. The stated role was superseded and the header never updated. |
| `src/SecureAD.Infrastructure/Findings/FindingsService.cs:163` comment | "Clear existing findings for this run (fresh run each time)". | `ClearFindingsForRun` receives a GUID generated four lines earlier and can never match a row. Nothing clears prior runs' findings. |

## Coverage gaps in this pass

Stated so they are visible. Read in full: `FindingsService.cs`, `FindingsService.Coverage.cs`,
`FindingsService.Persistence.cs`, `FindingsService.Suppression.cs`, `FindingsService.ActionReport.cs`,
`SuppressionService.cs`, `ActionPriorityCalculator.cs`, `IRuleEvaluator.cs`, `SuppressionEntry.cs`, and
the `ExecuteFindingsAsync` / `GenerateFindingsAsync` / `BackfillFindingPrincipals` regions of
`DerivedAnalysisPipeline.cs`.

Read in part: `FindingsPolicyEvaluator.cs` lines 1–180 of 482; `FindingsService.Enrichment.cs` 1–120 of
347; `FindingsService.Queries.cs` 1–130 of 294 plus `:192`; `ActionGrouper.cs` 1–110 of 305.

Not read in body — claims rest on call-site tracing and signatures, not internals:
`FindingsPolicyLoader.cs`, `FindingsPolicyAuditLog.cs`, `SuppressionMatcher.cs`,
`AcceptanceImportService.cs`, `Coverage/CoverageEnforcementService.cs`.

Deferred to `E-rules.md` by design: `RuleEvaluatorHelpers.cs` (1,154), the ten evaluators (4,270),
`rules.yaml` (673), `BuiltInRules`, `RuleDefinitionLoader`, `FindingEvidenceMatrix`,
`BroadPrincipalCatalog`, `UserRightCatalog`, `SigningHardeningCatalog`.
