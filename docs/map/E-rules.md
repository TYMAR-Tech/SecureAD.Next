# E — Findings & Rules (part 2: the rule catalogue)

**Owns:** everything behind `IRuleEvaluator.Evaluate` — the SEC-* catalogue, the ten evaluators that
implement it, the SQL surface they share, and the reference catalogues three of them consult. It
begins where [`E-findings.md`](E-findings.md) stops and produces the `FindingV2` instances E2 fans
out for, enriches, stamps and persists.

**Split note:** the seam is `IRuleEvaluator.Evaluate` (`Findings/IRuleEvaluator.cs`, 36 lines). E2
owns the registry, the parallel fan-out and the disabled-rule gate; this file does not re-describe
them. E4 owns the coverage verdict; this file only reports what the rule set actually declares.
Numbering continues from E15.

## The flow

1. **`BuiltInRules` initialises once, statically** (`BuiltInRules.cs:10`). Its static initialiser
   calls `RuleDefinitionLoader.LoadEmbeddedRules()`, which pulls
   `SecureAD.Core.Findings.Rules.rules.yaml` out of the assembly as an embedded resource and
   deserialises it with YamlDotNet under a camel-case naming convention. There is no file on disk at
   runtime and no reload path — the catalogue is fixed at compile time.
2. **62 rules are parsed.** Each yields a `FindingRule` carrying `RuleId`, `Name`, `Description`,
   `DefaultSeverity`, `Category`, `Remediation`, `MitreAttackId`, `Tags` and `EnabledByDefault`. An
   unparseable `severity` or `category` throws — the catalogue fails loudly rather than dropping a
   rule.
3. **`FindingsService.CreateDefaultEvaluators()`** (`FindingsService.cs:118`) constructs the ten
   evaluators. Each declares its `RuleIds` as a literal array in its own constructor initialiser; E2
   inverts those into `_ruleToEvaluator`. **61 of the 62 catalogue ids are claimed.** The 62nd,
   `SEC-041`, is `enabled: false` and has no evaluator at all.
4. **E2 calls `Evaluate(ruleId, context, ct)` once per rule id**, in ordinal order within each
   evaluator. The `RuleEvaluationContext` carries four things: an open `SqliteConnection`, the
   privileged-SID set built in step 5 of E-findings, `RunGeneratedUtc` and `RunId`. It carries no
   coverage state and no policy — an evaluator cannot know whether its own inputs were captured.
5. **Every evaluator dispatches on a `switch` over its rule ids** to a private static method, falling
   through to `_ => []`. The dispatch is exhaustive against `RuleIds` in all ten, so the fallthrough
   is unreachable in practice; it exists so an id present in `RuleIds` but not the switch degrades to
   zero findings rather than throwing.
6. **Six rules do no work of their own.** `SEC-001`, `SEC-003`, `SEC-004`, `SEC-005` and `SEC-006`
   are one-line delegations to `RuleEvaluatorHelpers.EvaluateControlEdgeRule` /
   `EvaluateControlEdgeOnAdminTarget` (E26) with a `ControlType` and a target filter; `SEC-002`
   (DCSync) is the only member of `ControlEdgeRuleEvaluator` with its own SQL, because it needs a
   self-join to prove a principal holds `GetChanges` **plus** one of the two companion rights.
7. **The other rules issue their own SQL.** Each opens a command on `context.Connection`, reads a
   result set, filters in C# (`IsAdminSid`, `IsPrivilegedPrincipal`, `IsBroad`), and constructs
   findings through one of the three factories in E25 — `CreateEdgeFinding` (edge-backed),
   `CreateDelegationFinding` (context-backed) or `CreatePathFinding` (path-backed).
8. **Schema is probed, not assumed.** `TableExists` and `ColumnExists` (E24) gate several queries:
   `EscalationPathRuleEvaluator` falls back to a tier-free query when `dim_asset_tier` is absent, and
   projects a literal `NULL` for `canonical_signature` when the column is missing.
9. **Three evaluators consult reference catalogues.** `GpoRuleEvaluator` reads `UserRightCatalog`
   (SEC-064) and `SigningHardeningCatalog` (SEC-066); `GpoRuleEvaluator`,
   `GroupMembershipRuleEvaluator`, `LapsRuleEvaluator` and `RuleEvaluatorHelpers` all read
   `BroadPrincipalCatalog`.
10. **Severity comes from one place.** Every evaluator calls `SeverityOf(ruleId)`, which reads
    `BuiltInRules.ById[id].DefaultSeverity` and falls back to `Medium` for an unknown id. No
    evaluator hardcodes a severity.
11. **Findings are returned, not written.** An evaluator has no write access and no knowledge of
    `fact_finding`. Everything after this point — enrichment, coverage stamping, sorting, the single
    insert transaction — is E2's, described in E-findings steps 8–13.
12. **`FindingEvidenceMatrix` is not consulted at runtime.** It states, per rule, which evidence
    shape backs it and which UI affordance that implies. It is read by `HelpViewModel` and by its own
    parity test, and by nothing on the evaluation path.

The shape of this half is set by steps 6 and 10. The rule catalogue and the evaluators are two
representations of the same 61-item set held in agreement by parity tests rather than by
construction, and the yaml file carries five fields that only the UI reads alongside two the run
depends on.

## Components

### E16 — Rule catalogue
- **Layer:** Core
- **Owns:** the identity, default severity, category, remediation text, MITRE mapping and enabled
  flag of every SEC-* rule.
- **Depends on:** —
- **Implemented by:** `Core/Findings/Rules/rules.yaml` (673), `Core/Findings/RuleDefinitionLoader.cs`
  (82), `Core/Findings/BuiltInRules.cs` (15), `Core/Findings/FindingRule.cs` (34),
  `Core/Findings/RuleCategory.cs` (37), `Core/Findings/Severity.cs` (22)
- **Non-obvious:** the yaml is **two catalogues in one file**. The run reads exactly two fields —
  `DefaultSeverity` (via `SeverityOf`, E23) and `EnabledByDefault` (via E2's parallel-path gate). The
  other five — `Name`, `Description`, `Remediation`, `Mitre`, `Tags` — have no consumer outside J
  (`FindingDetailViewModel:276–281`, `RuleHelpViewModel:52–57`, `HelpViewModel.Content.cs`). A
  rebuild that split them would let the run-time table be a 61-row constant and the presentation
  catalogue be data.

  `BuiltInRules.All` is a **static property initialiser that does file I/O** — a manifest-resource
  read and a YAML parse on first touch of the type, from whichever thread gets there first. E2's
  parallel fan-out touches it from ten threads; it is safe only because the CLR guarantees
  static-initialiser exclusivity, which is load-bearing here and stated nowhere.

  **62 rules, 61 evaluated.** `SEC-041` (Certificate Auto-Enrollment for Non-Admin) is
  `enabled: false` and has **no evaluator**. This settles the open question E2 left about the
  disabled-rule gate: the gate is applied on the parallel path only, so a disabled rule *would* run
  in-memory — but the only disabled rule has no evaluator to run, so the asymmetry currently has no
  observable effect. It is a latent bug, not a live one. `SEC-041` nonetheless survives in five other
  places: a `Disabled` entry in E17, a `docs/rules/` card, a report-catalogue label, a UI category
  grouping (`FindingsGridViewModel.cs:87`) and the synthetic DB generator.

  **Cross-branch output:** J reads this for rule help, MITRE links and the category filter. I
  (`ReportCatalog.cs:339`) hardcodes its own rule-id-to-name list rather than reading `BuiltInRules`
  — a second catalogue nothing holds in parity.

### E17 — Rule evidence matrix
- **Layer:** Core
- **Owns:** the per-rule statement of which evidence a finding rests on and which detail affordance
  the UI must therefore offer.
- **Depends on:** E16
- **Implemented by:** `Core/Findings/FindingEvidenceMatrix.cs` (143)
- **Non-obvious:** ruled E's rather than J's in the README's boundary table, and this is where it
  lands. It is a **contract about the rule set**, not about rendering: `FindingEvidenceShape` has
  five values (`Disabled`, `ControlEdge`, `EscalationPath`, `DirectAce`, `Context`) and each entry
  also names the evaluator and the source table. That makes it the only place where "SEC-013 is
  backed by `dim_delegation` and evaluated by `DelegationRuleEvaluator`" is written down as data —
  the evaluators themselves record it only in prose doc-comments.

  It is **redundant by construction and unenforced against reality.** Nothing checks that the
  `Evaluator` string matches the type that actually declares the rule id, or that the `EvidenceShape`
  matches which factory the evaluator calls. `FindingEvidenceMatrixTests` (70 lines) checks the
  matrix against `BuiltInRules` — that every rule has exactly one entry — not against the evaluators.
  A rule moved between evaluators would leave this silently wrong.

  **Cross-branch output:** its only production consumer is `HelpViewModel` (J).

### E18 — Control-edge rules
- **Layer:** Infrastructure
- **Owns:** the rules that fire on a single ACE-derived control edge, and the advanced
  multi-condition variants of them.
- **Depends on:** D (`fact_control_edge`), B (`dim_object`, `fact_ace`), E16, E23, E25, E26
- **Implemented by:** `Findings/Evaluators/ControlEdgeRuleEvaluator.cs` (105),
  `Findings/Evaluators/AdvancedRuleEvaluator.cs` (471)
- **Non-obvious:** these two are grouped because they read the same evidence — `fact_control_edge`,
  plus `fact_ace` for the AdminSDHolder case — and because `ControlEdgeRuleEvaluator` is 105 lines of
  which 65 are one rule. Splitting them into two components would give one component with six rules
  and almost no code.

  `SEC-002` (DCSync) is the only rule here with its own query, and the reason is worth keeping:
  DCSync is not one right but a conjunction, so it self-joins `fact_control_edge` to prove
  `GetChanges` **and** one of `GetChangesAll` / `GetChangesInFilteredSet` on the same target, then
  `GROUP BY`s to collapse the two companion rights into one deterministic row. The comment explains
  that without the `GROUP BY`, E2's `INSERT OR IGNORE` would keep whichever row the engine yielded
  first and the persisted `Detail` would non-deterministically drop one of the rights. That is a real
  defect prevented by a comment-documented `GROUP BY`.

  `SEC-006` is the visible face of `[IMP-CTRL-SCOPE]`: it does not match the literal `AddMember` edge
  but `PropertyWriteEquivalents(AddMember)` — `AddMember` plus
  `GenericAll`/`GenericWrite`/`WriteAllProperties` — constrained to `object_class = 'group'`. The
  constraint is mandatory, because the broad rights are not class-scoped; a rebuild that widened a
  rule without the class clause would fire "can add members" on a computer.

  **`AdvancedRuleEvaluator` is a grab-bag**, and its own doc comment gives it away: "SEC-120 through
  SEC-204: AdminSDHolder backdoor, DC OU write access, RBCD on DC, WriteSidHistory,
  ReplicationTopology, privileged static-password accounts, privileged delegation,
  WriteDACL/WriteOwner on domain root, spill to Tier-0." Nine rules with no shared subject. It is the
  file rules were added to when no existing evaluator matched.

### E19 — Object-attribute rules
- **Layer:** Infrastructure
- **Owns:** the rules that fire on an account's own stated attributes — delegation flags, SPNs, UAC
  bits, `adminCount`, ownership.
- **Depends on:** B (`dim_object`, `dim_delegation`, `dim_principal`), D6
  (`fact_group_membership_closure`, `v_group_membership_effective`), E16, E23, E24, E25, E27
- **Implemented by:** `Findings/Evaluators/KerberosRuleEvaluator.cs` (414),
  `Findings/Evaluators/DelegationRuleEvaluator.cs` (388),
  `Findings/Evaluators/AccountHygieneRuleEvaluator.cs` (305),
  `Findings/Evaluators/ServiceAccountRuleEvaluator.cs` (202)
- **Non-obvious:** four files, one evidence shape. Every rule here answers "is this account
  configured dangerously?" from `dim_object` / `dim_delegation` columns, and all of them produce
  **context-backed** findings via `CreateDelegationFinding` rather than edge-backed ones — E17
  classifies SEC-010 through SEC-013 as `Context`, and the same holds across the group. The four
  files exist because they were written at different times, not because the evidence differs.

  The exceptions prove the grouping rather than breaking it: `SEC-014` (who can *write*
  `msDS-AllowedToActOnBehalfOfOtherIdentity`) and `SEC-024`/`SEC-025` (who can write an SPN or a key
  credential) reach into `fact_control_edge`, because "who could set this attribute" is a
  control-edge question wearing an attribute rule's name. A rebuild would put those three in E18.

  **`AccountHygieneRuleEvaluator`'s own summary is wrong.** It claims "SEC-030 through SEC-032,
  SEC-040, SEC-060 through SEC-062"; its `RuleIds` are `SEC-030, 031, 032, 040, 061, 062`. `SEC-060`
  lives in `GroupMembershipRuleEvaluator` (E20). The doc comment describes a division of labour that
  no longer holds.

  `ServiceAccountRuleEvaluator` is the cleanest of the ten and the one to copy: 202 lines, three
  rules, and it composes its `WHERE` clause from `ServiceAccountClassifier.BuildSqlPredicate` and
  `PrivilegedGroupCatalog.BuildSqlPredicate` rather than restating either in SQL — so the C#
  definition of "service account" and the SQL that finds them cannot drift.

### E20 — Membership-shape rules
- **Layer:** Infrastructure
- **Owns:** the rules that fire on the shape of group membership rather than on any one principal —
  group size, nesting depth, cycles, and broad principals holding control.
- **Depends on:** D6 (`fact_group_membership_closure`, `fact_group_membership_direct`), D
  (`fact_control_edge`), E16, E23, E24, E25
- **Implemented by:** `Findings/Evaluators/GroupMembershipRuleEvaluator.cs` (778)
- **Non-obvious:** kept separate from E19 despite both reading membership, because the *subject*
  differs: E19 asks about an account and joins membership to classify it; E20 asks about a group and
  its closure. `SEC-050` (large privileged group), `SEC-051` (nested groups in Domain Admins) and
  `SEC-052` (circular membership) have no per-account analogue.

  At 778 lines it is the largest single evaluator, and two of its five rules — `SEC-060` (broad SID
  with write access) and `SEC-063` (broad control over containers) — are control-edge rules that
  landed here because "broad principal" felt like a membership concept. They belong in E18.

  `GroupHasObservedMembers` and `IsGroupMembershipCoverageComplete` (E24) exist for this component: a
  group with zero rows in the closure table is indistinguishable from a group that is genuinely
  empty, and `SEC-050`'s "this group is too large" inverts into a silent false negative when the
  closure is incomplete. **Cross-branch input:** this is the component most exposed to D6 having
  degraded.

### E21 — GPO and SYSVOL rules
- **Layer:** Infrastructure (evaluators) / Core (catalogues)
- **Owns:** the rules that read policy content — Group Policy settings, SYSVOL file ACLs, and LAPS
  configuration — rather than directory objects.
- **Depends on:** B (`dim_gpo_setting`, `fact_sysvol_ace`, `fact_ace`), D (`fact_control_edge`), D6
  (`v_group_membership_effective`), E16, E23, E24, E25
- **Implemented by:** `Findings/Evaluators/GpoRuleEvaluator.cs` (616),
  `Findings/Evaluators/LapsRuleEvaluator.cs` (629), `Core/Findings/UserRightCatalog.cs` (102),
  `Core/Findings/SigningHardeningCatalog.cs` (156)
- **Non-obvious:** these two evaluators are the only ones whose evidence is not the directory.
  `SEC-064`, `SEC-065` and `SEC-066` read `dim_gpo_setting` — parsed `GptTmpl.inf` content — and
  `SEC-082`/`SEC-083` read `fact_sysvol_ace` and SYSVOL file content. That is why they are the only
  rules whose `RuleCoverageRequirements` entries name `CoverageModules.Sysvol`.

  **The two Core catalogues exist because policy findings are unactionable without reference data.**
  `UserRightCatalog` maps each `Se*Privilege` constant to its Microsoft-documented default holders,
  so `SEC-064` fires only on a grant *beyond* the baseline; its remarks state explicitly that
  per-server-role exactness is deliberately not modelled, because that is CIS-benchmark completeness
  rather than "someone dangerous holds this right". `SigningHardeningCatalog` carries a per-setting
  `SecureValue` **and** a `SecureComparison` (`EqualsSecure` vs `AtLeastSecure`) because SMB signing
  is secure at exactly 1 while LDAP server signing is secure at 2 or above — a flat "1 = secure"
  check would be wrong for half the settings. Both are grounded per-entry in first-party Microsoft
  sources. This is the best-sourced code in the branch.

  They are Core types with a single Infrastructure consumer each, which is why they are mapped here
  rather than as their own component: the catalogue and the rule that reads it are one responsibility
  split across two projects for testability.

  `SEC-080` and `SEC-082` are deliberately unioned (`[IMP-GPO-SYSVOL]`): a GPO can be modified
  through a directory ACE *or* through write access to its SYSVOL policy folder, so
  `EvaluateGpoModify` pre-loads the SYSVOL writers per GPO to flag when the same GPO has both paths.
  Two capture sources reconciled into one finding — the right call, and it depends on B having
  captured SYSVOL.

  `LapsRuleEvaluator`'s confidential-attribute gate is the most technically load-bearing comment in
  the branch: LAPS password attributes are flagged `fCONFIDENTIAL`, so per KB922836 a plain
  `READ_PROPERTY` grant — which every authenticated user holds by default — cannot read them, and the
  rule must gate on `access_mask & 0x100` (`CONTROL_ACCESS`) instead. Without that, `SEC-090` would
  fire on every account in the domain.

### E22 — Escalation-path rules
- **Layer:** Infrastructure
- **Owns:** turning D's computed escalation paths into findings, tiered by what the path reaches and
  how far it travels.
- **Depends on:** D (`fact_escalation_path`), D11 (`dim_asset_tier`), B (`dim_principal`), E16, E24,
  E25
- **Implemented by:** `Findings/Evaluators/EscalationPathRuleEvaluator.cs` (362)
- **Non-obvious:** alone among the ten in three ways, which is why it is its own component. It is the
  only evaluator that produces **path findings** via `CreatePathFinding`; the only one whose findings
  carry their **own per-row `coverage_complete`**, read from `fact_escalation_path` and preserved by
  E2's stamper rather than computed; and the only one that **consumes a D output wholesale** rather
  than querying stated facts.

  Its eight rules are one parameterised query invoked eight ways: `EvaluateByTier` with a tier and a
  hop-count bound for SEC-070 through SEC-075, `EvaluateByTierReason` with a substring token for
  SEC-076/077. The tokens come from `TierReasonCatalog` rather than being literals, so the writer
  (`DerivedAssetTierClassifier`, D) and this reader cannot drift — `[IMP-REASON-DRIFT]`.

  **The `main.` qualifier on `dim_asset_tier` is load-bearing and documented.** This evaluator runs
  on a factory read connection where `DatabaseConnectionFactory` has created a precedence temp view
  of the same name; unqualified, the join would bind to the temp view and a later policy tier change
  would retroactively alter which findings a signed snapshot contains. `docs/DATA-MODEL.md:21` states
  the same rule. The remarks note that removing `main.` is the whole of the change if the owner ever
  decides policy should reach analysis — one word, in two places, deliberately. This is the clearest
  example in the branch of a decision recorded at the point of use.

  Two back-compatibility paths live here: `EvaluateByFallbackTier` when `dim_asset_tier` is absent,
  and a literal `NULL` projection when `fact_escalation_path.canonical_signature` is missing. Per
  `.github/copilot-instructions.md` there will be no older bundles in the field, so both are
  carve-outs for a case that cannot occur.

  The `IsTier0Action` comments at `:79` and `:252` assert agreement with E12's
  `ActionPriorityCalculator`. E12 already records that this agreement is maintained by comment, with
  no call, no shared code and no test — except that `LoadStructuralTier0TargetSids` decides
  membership in C# via `WellKnownSidCatalog` specifically so it agrees with that calculator instead
  of restating the RID rules in SQL. So the structural floor is shared; the Tier-0 *action*
  definition is not.

### E23 — Rule metadata resolution and principal classification
- **Layer:** Infrastructure (with a Core catalogue)
- **Owns:** answering "how severe is this rule?" and "what kind of principal is this SID?"
  identically for every evaluator.
- **Depends on:** E16, B (`Tier0RidCatalog`, `WellKnownSidCatalog`)
- **Implemented by:** `Findings/RuleEvaluatorHelpers.cs` `:20–200` and `:947–1005` (≈240 lines),
  `Findings/BroadPrincipalCatalog.cs` (107)
- **Non-obvious:** the first of five components inside the 1,154-line `RuleEvaluatorHelpers`. This
  one holds `SeverityOf` (`:78`), `BroadPropertyWriteRights` / `PropertyWriteEquivalents` (`:61`,
  `:71`), the static SID sets (`PrivilegedSystemSids`, `Sec030OperatorGroupSids`, `BroadSids`,
  `AdminRids`), `IsAdminSid` (`:120`), `IsPrivilegedPrincipal` (`:139`),
  `ShouldExcludePrivilegedTrustee` (`:160`), `ClassifyPrincipal` (`:163`) and the
  `PrincipalClassification` record, plus the target-side predicates `IsTierZeroTarget` (`:947`),
  `IsBroadSidTargetTierZero` (`:963`) and `ResolveBroadSidName` (`:985`).

  `AdminRids` delegates to `Tier0RidCatalog.ExpectedAdminRids` and its remarks record the one
  difference from `Tier0RidCatalog.Tier0Rids`: Group Policy Creator Owners (RID 520) is excluded,
  because its privilege is *not* unremarkable — decision 0006. The distinction between "this SID is
  privileged, so target it" and "this SID is privileged, so a finding about it is expected" is one
  RID wide and is documented in exactly one place.

  `BroadPrincipalCatalog` is folded in here rather than mapped separately because
  `IsBroadPrincipalSid` (`:185`) and `ResolveBroadSidName` (`:985`) are one-line delegations to it.
  `[IMP-BROAD-DRIFT]` records the reason it exists: the classifier, `SEC-060`'s SQL emitter and the
  display-name resolver must share one definition of "broad", or a rule fires on a principal the UI
  cannot name.

  `docs/review/01-infrastructure-storage.md:481` records that `ReportCatalog` SQL restates "principal
  is not a well-known admin" inline, duplicating `IsAdminSid`. That duplicate is I's, not E's, but it
  is a duplicate of this component.

### E24 — SQLite dialect fragments and schema probes
- **Layer:** Infrastructure
- **Owns:** the SQL snippets and schema questions every evaluator would otherwise write for itself.
- **Depends on:** C1 (the schema being probed), E4 (`CoverageModules`)
- **Implemented by:** `Findings/RuleEvaluatorHelpers.cs` `:201–232`, `:254–324` and `:1053–1154`
  (≈205 lines)
- **Non-obvious:** four unrelated jobs sharing a section. **Predicate emitters:** `NotDisabledSql`
  (`:201`) encodes the UAC `ACCOUNTDISABLE` bit test once; `FileTimeToUnixEpochSql` (`:211`) encodes
  the Windows-FILETIME-to-epoch arithmetic once; `ShortSpnHostSql` (`:226`) extracts the host portion
  of an SPN in SQL. **Schema probes:** `TableExists` (`:298`) and `ColumnExists` (`:306`). **Coverage
  questions:** `GroupHasObservedMembers` (`:254`) and `IsGroupMembershipCoverageComplete` (`:272`).
  **Domain-controller identification:** four overlapping members at `:1053`, `:1067`, `:1115` and
  `:1141` — two SQL emitters, one shadow-aware variant, and a C# predicate.

  That last cluster is the component's problem in miniature. `IsDomainControllerSql` exists in a
  static form and a connection-taking form that adapts to available columns, plus
  `IsDomainControllerOrChildShadowSql`, plus `IsDomainController(objectClass, uac, primaryGroupId,
  dn)`. Four ways to ask one question, and the SQL and the C# can disagree about a given object
  without anything noticing.

  A rebuild should note *why* this exists at all: SQLite has no user-defined functions registered
  here, so a predicate shared across rules must be a string. That is a defensible response to the
  constraint, and it is the reason `SEC-011`'s "is this a DC" and `SEC-101`'s cannot simply call the
  same method.

### E25 — Finding construction and context JSON
- **Layer:** Infrastructure
- **Owns:** turning a query row into a `FindingV2` with a stable key, a deterministic `Detail` string
  and a well-formed `ContextJson`.
- **Depends on:** E15 (`FindingV2`), E23 (`ClassifyPrincipal`), B (`dim_object`)
- **Implemented by:** `Findings/RuleEvaluatorHelpers.cs` `:325–773` (≈449 lines)
- **Non-obvious:** the largest of the five and the one with the strongest claim to being its own
  type. Three public factories — `CreateEdgeFinding` (`:325`), `CreateDelegationFinding` (`:432`),
  `CreatePathFinding` (`:512`) — map exactly onto three of E17's five `FindingEvidenceShape` values,
  so the choice of factory *is* the evidence classification, made implicitly at each of ~90 call
  sites.

  Roughly half the section (`:569–747`) is path-detail parsing: `ParsePathSteps`, `TryParsePathStep`,
  six `Require*`/`TryGet*` `JsonElement` accessors, and two private context records. This exists
  because D writes `fact_escalation_path.path_detail` as a JSON string rather than as rows, so E22
  must re-parse D's own serialisation to build a finding's context. **Cross-branch dependency worth
  naming in a rebuild:** the price of D storing a structure as text is ~180 lines of hand-written
  JSON destructuring in E.

  `ContextJsonOptions` (`:20`) sets `JavaScriptEncoder.UnsafeRelaxedJsonEscaping` with a comment
  explaining that `ContextJson` is stored in SQLite and rendered in UI and reports but never embedded
  in HTML, so the default HTML-safe encoder's `\u002B` for `+` only clutters strings like
  "GetChanges + GetChangesAll". Correct reasoning, and the "never embedded in HTML" premise is a
  constraint on I and J that lives only in this comment.

  `HashPathSignature` (`:504`) produces the stable identity for path findings — pinned by
  `PathFindingKeyStabilityTests`.

  **This is where the live copies of `TruncatePathDetail` (`:748`) and `GetDomainObjectGuid` (`:757`)
  sit.** E6 records that `FindingsService.Persistence.cs:68` and `:77` hold private duplicates with
  zero callers. Verified: the four production call sites for `TruncatePathDetail` are all in
  `EscalationPathRuleEvaluator` (`:128`, `:129`, `:205`, `:349`) and all resolve to this copy. The
  `Persistence.cs` pair are dead and shadowed.

### E26 — Shared control-edge evaluator
- **Layer:** Infrastructure
- **Owns:** the two generic control-edge queries that five rules are entirely implemented by.
- **Depends on:** D (`fact_control_edge`), B (`dim_object`), E16, E23, E25
- **Implemented by:** `Findings/RuleEvaluatorHelpers.cs` `:774–946` (≈173 lines)
- **Non-obvious:** **this is not a helper.** `EvaluateControlEdgeRule` (`:774`, `:789`) and
  `EvaluateControlEdgeOnAdminTarget` (`:860`, `:876`) take a `RuleEvaluationContext`, run a query,
  filter, and return `IReadOnlyList<FindingV2>`. That is `IRuleEvaluator.Evaluate`'s signature in all
  but name. `SEC-001`, `SEC-003`, `SEC-004`, `SEC-005` and `SEC-006` have no implementation of their
  own — `ControlEdgeRuleEvaluator` is a switch that forwards to this file. It is a rule engine hiding
  inside a static helper class, and it is the single strongest argument for the split proposed in
  Would-do-differently.

  Both methods exist in a single-`ControlType` overload and an `IReadOnlyCollection<ControlType>`
  overload; the single-type form delegates to the set form. The set form was added by
  `[IMP-CTRL-SCOPE]` and carries the safety rule in its own doc comment: when the set includes the
  class-agnostic broad rights, a `targetObjectClass` constraint is **mandatory**, or the rule fires
  on a capability the target class cannot have. That invariant is enforced by prose, not by the type
  system — a rebuild should make it impossible to pass a broad set without a class.

  Both `GROUP BY (source_sid, target_object_guid)` with `MIN(control_type)`, for the reason SEC-002
  gives: without it, a principal holding both a specific right and a broad grant produces two rows
  and E2's `INSERT OR IGNORE` keeps a non-deterministic one.

### E27 — Directory value parsers
- **Layer:** Infrastructure
- **Owns:** reading structure out of the raw attribute values captured verbatim — SPN strings and
  binary security descriptors.
- **Depends on:** B (the captured values)
- **Implemented by:** `Findings/RuleEvaluatorHelpers.cs` `:234–253` and `:988–1052` (≈85 lines)
- **Non-obvious:** the smallest of the five and the one most obviously misplaced. `IsKrbtgtSid`
  (`:234`), `HasServiceSpnPrefix` (`:242`), `FindFirstServiceSpn` (`:988`) and
  `ExtractRbcdTrusteeSids` (`:1007`) are pure functions over captured strings and bytes, with no
  database access, no rule knowledge and no `RuleEvaluationContext`.

  `ExtractRbcdTrusteeSids` **parses a base64 binary security descriptor in the findings layer** to
  recover the trustees of `msDS-AllowedToActOnBehalfOfOtherIdentity`. B already has a
  security-descriptor parser; this is a second one, reached only because `dim_delegation` stores the
  RBCD descriptor as an opaque blob rather than as parsed trustee rows. That is a capture-shape
  decision paid for here, and it is a genuine cross-branch finding: had B exploded RBCD trustees at
  capture time the way it explodes ACEs, this would not exist.

  `ServiceSpnPrefixes` (a 15-entry array at `:104`, read by `HasServiceSpnPrefix` and
  `FindFirstServiceSpn`) exists to reduce Kerberoast false positives. It is an allow-list of
  recognised Windows SPN prefixes with no source citation, unlike E21's catalogues — and it belongs
  in Core with the others.

## Naming & taxonomy

| Current | Proposed | Why it matters |
|---|---|---|
| `RuleEvaluatorHelpers` | split into five, per E23–E27 — e.g. `RuleSeverity`+`PrincipalClassifier`, `FindingsSql`, `FindingFactory`, `ControlEdgeRuleEngine`, `DirectoryValueParsers` | "Helpers" is a name that means "things with no home", and it has behaved like one: 1,154 lines, `internal static`, imported with `using static` by all ten evaluators. Two of the five things inside it are not helpers — E26 is a rule engine and E25 is a factory with an implicit evidence-classification decision in it. The name is why nobody noticed. |
| `AdvancedRuleEvaluator` | delete the name; redistribute SEC-120…SEC-204 to E18 and E19 by evidence | "Advanced" is not a category, it is a timestamp — it means "added after the categorised evaluators existed". Its nine rules share no subject. Any rebuild that keeps this name will grow a tenth grab-bag. |
| `EvaluateControlEdgeRule` / `EvaluateControlEdgeOnAdminTarget` (in `RuleEvaluatorHelpers`) | `ControlEdgeRuleEngine.EvaluateAnyTarget` / `.EvaluatePrivilegedTarget` | The current names are indistinguishable at a call site, and "OnAdminTarget" understates what it does: it filters targets through `IsPrivilegedPrincipal` against the *run's computed* privileged set, not against a static admin list. A reader assumes RIDs; it is D6's closure. |
| `AccountHygieneRuleEvaluator` | `AccountConfigurationRuleEvaluator`, and fix its summary | "Hygiene" reads as low-severity cleanup, but `SEC-031` (non-default owner on an admin object) is High. Separately, its doc comment claims `SEC-060`, which lives in `GroupMembershipRuleEvaluator` — the comment describes a boundary that has moved. |
| `BuiltInRules` | `RuleCatalog` | "Built-in" contrasts with a user-supplied catalogue that does not exist and, since the yaml is an embedded resource with no reload path, cannot. The name promises extensibility the design deliberately excludes. |
| `FindingRule.EnabledByDefault` | `Enabled` | There is no per-run override — the only reader is E2's gate on the catalogue value. "ByDefault" implies something can override it; nothing can. |
| `rules.yaml` | split into `rule-severity.yaml` (id, severity, enabled) and `rule-reference.yaml` (name, description, remediation, mitre, tags) | 673 lines in which the run reads two fields per rule and the UI reads five. Editing severity — a behaviour change — and editing remediation text — a copy change — are the same file edit today, with the same review weight. |
| `FindingEvidenceMatrixEntry.Evaluator` (a `string`) | drop it, or derive it | A type name held as a string, checked by nothing. It is the only field in the matrix that can be wrong without any test failing. |
| `IsDomainControllerSql` (three overloads) + `IsDomainController` | one `DomainControllerPredicate` with an explicit `AsSql()` / `Matches()` pair | Four members, one question, two languages, no test that they agree. |

## Would-do-differently

**Give the shared control-edge engine a name and a home.** E26 is the structural error of this half.
Five of the sixty-one rules have their entire implementation inside a file called `Helpers`, reached
through a `using static` import, invoked by a switch arm that reads like configuration. The
consequence is that `ControlEdgeRuleEvaluator.cs` is 105 lines and looks trivial while owning five
Critical rules. Next time: a `ControlEdgeRule` that takes `(ruleId, controlTypes, targetPredicate)`
as data, registered in a table, so that adding SEC-006's class constraint is filling in a field
rather than remembering a prose invariant.

**Make an evaluator declare its own data dependencies.** E4 records that `RuleCoverageRequirements`
is a hand-maintained dictionary in `FindingsService.cs` and the only thing that knows what a rule
reads; the evaluators do not declare it. Every one of the 61 entries is derivable from the SQL the
evaluator actually runs — `fact_control_edge` implies `ControlEdges`, `fact_sysvol_ace` implies
`Sysvol`, `v_group_membership_effective` implies `GroupMembership`. Having the evaluator declare
`IReadOnlyList<string> RequiredModules` next to `RuleIds` would put the declaration beside the query
it describes, and would delete a 61-line table maintained in a different file by a different person
at a different time.

**Do not make an evaluator responsible for parsing another branch's serialisation.** ~180 lines of
E25 exist to re-parse `fact_escalation_path.path_detail`, a JSON string D writes. Store path steps as
rows and this component loses a third of its size and all of its `JsonElement` accessors.

**Do not parse a security descriptor twice.** `ExtractRbcdTrusteeSids` (E27) exists because
`dim_delegation` keeps the RBCD descriptor as an opaque base64 blob. B already parses descriptors
into `fact_ace`. Exploding RBCD trustees at capture time would delete this function and let
SEC-013/SEC-014 be ordinary joins.

**Ten evaluators was too many; five is closer.** Grouping by evidence source rather than by topic —
E18 control edges, E19 object attributes, E20 membership shape, E21 policy content, E22 escalation
paths — matches how the rules actually differ. The current ten grouped by *subject matter*, which is
why `SEC-060` is in the membership file, `SEC-024` is in the Kerberos file while querying control
edges, and `AdvancedRuleEvaluator` is a residue. Evidence grouping also aligns with coverage: all
five components map cleanly onto `CoverageModules`, which is exactly what E4's table has to state by
hand today.

**Remove the two back-compatibility paths in E22.** `EvaluateByFallbackTier` (absent
`dim_asset_tier`) and the `canonical_signature` `NULL` projection both handle bundle shapes that, per
`.github/copilot-instructions.md`, will not exist in the field. They are untested branches that
change which findings are produced.

**This was right, keep it: severity has exactly one source, and every evaluator uses it.**
`SeverityOf(ruleId)` reads `BuiltInRules.ById[id].DefaultSeverity`, and across 4,270 lines of
evaluator there is not one hardcoded severity literal. Changing SEC-021 from Critical to High is a
one-line yaml edit that cannot leave a stale copy behind. Given how many other things in this branch
exist in two or four copies held together by comments — Tier-0 definitions, DC predicates,
rule-id-to-name maps, security-descriptor parsers — the discipline on severity stands out, and a
rebuild should extend the same pattern to the rest rather than dilute it.

**Also right, keep it: the reference catalogues cite their sources per entry.** `UserRightCatalog`
and `SigningHardeningCatalog` (E21) each ground every value in a named first-party Microsoft document
and state explicitly what they deliberately do *not* model. Security tooling that asserts "this value
is wrong" without saying on whose authority is unauditable; these two are the counter-example and the
standard to hold the rest to.

## Corrections to existing documents

| Document | Claim | Correction |
|---|---|---|
| `docs/map/E-findings.md`, E4 | "`RuleCoverageRequirements` is a 64-entry hand-maintained dictionary" | It has **61** entries (`FindingsService.cs:29–92`), and the key set is *exactly* the union of the ten evaluators' `RuleIds` — no rule is missing an entry and no entry is orphaned. |
| `docs/map/E-findings.md`, E4 | "A new rule added without an entry here falls through to the heuristic default (`[Objects]`) … a silent wrong answer" | The risk is real but currently has **zero instances**, and `RuleCatalogParityTests.EveryEnabledCatalogRule_HasCoverageRequirement` plus `EveryEvaluatorRuleId_ExistsInCatalog` close it together: a rule can only reach an evaluator via `rules.yaml`, and every enabled yaml rule must have a coverage entry. The hole is a test away from reopening, not open. |
| `docs/map/E-findings.md`, E2 | "a disabled rule runs against an in-memory database and does not run against a file-backed one … the disabled-rule gate is exercised in exactly the configuration where it is not tested" | Correct as a description of the code, but the **only** disabled rule is `SEC-041`, which has no evaluator, so the asymmetry currently produces no divergence in either configuration. Latent, not live. |
| `docs/map/E-findings.md`, E12 | The Tier-0 agreement between `EscalationPathRuleEvaluator` and `ActionPriorityCalculator` is "maintained by assertion" with "no call, no shared code, no test" | Partly superseded: `LoadStructuralTier0TargetSids` decides the structural Tier-0 **floor** in C# via `WellKnownSidCatalog` specifically so it agrees with `ActionPriorityCalculator` rather than restating the RID rules in SQL (`[F-01-12]`, pinned by `StructuralTier0FloorTests`). The shared floor is real; only the Tier-0 *action* definition is comment-only. |

## Coverage gaps in this pass

- **Read in full:** `IRuleEvaluator.cs`, `BuiltInRules.cs`, `RuleDefinitionLoader.cs`,
  `ControlEdgeRuleEvaluator.cs`, `RuleCardParityTests.cs`, `RuleCatalogParityTests.cs`.
- **Read in part:** `RuleEvaluatorHelpers.cs` — lines 1–130 and 774–960 read; the remaining ~840
  lines were mapped from the full member list with line numbers, not read line by line. The E23–E27
  boundaries are drawn from member signatures and placement; a member could be mis-assigned within a
  component without changing the split.
- **Read in part:** `EscalationPathRuleEvaluator.cs` (1–120 of 362); `GpoRuleEvaluator.cs` (1–60 of
  616); `FindingEvidenceMatrix.cs` (1–70 of 143); `UserRightCatalog.cs` (1–60 of 102);
  `SigningHardeningCatalog.cs` (1–40 of 156); `rules.yaml` (1–30 of 673, plus a full mechanical
  extraction of ids and `enabled` flags).
- **Contract surface only:** `AdvancedRuleEvaluator`, `KerberosRuleEvaluator`,
  `DelegationRuleEvaluator`, `AccountHygieneRuleEvaluator`, `GroupMembershipRuleEvaluator`,
  `ServiceAccountRuleEvaluator`, `LapsRuleEvaluator` — `RuleIds`, class doc-comment, referenced
  tables and helper call counts were extracted mechanically; individual rule bodies were not read.
  **Per-rule detail inside these seven is the main gap**, and would be the first thing to fill if
  this map is ever taken to class level. It does not affect the component boundaries, which are drawn
  on evidence source.
- **Not read:** `FindingsServiceTests.cs` (14,519 lines) — the parity and invariant fixtures were
  read instead, on the grounds that they assert the contracts this file describes; the behavioural
  tests assert individual rule outcomes, which sit below this map's altitude.
- **Not verified:** whether `BroadPrincipalCatalog`'s exact-SID set agrees with
  `WellKnownSidCatalog`'s. `ReportSqlRidDriftGuardTests` exists and appears to guard a related
  question for I.
