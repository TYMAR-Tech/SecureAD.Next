# Data Model

## Overview

SecureAD stores all data in a single SQLite database (`audit.db`). The schema follows a star-schema-like pattern with dimension tables (`dim_*`), fact tables (`fact_*`), and grid views (`v_grid_*`).

One exception: user-editable state lives in a **suppression sidecar**, `suppressions.db`, kept beside `audit.db` in the run bundle. It holds `dim_suppression`, `dim_sidecar_meta`, and `dim_asset_tier_policy`, and nothing else. `audit.db` is signed at capture, so writing acceptances or tier overrides into it would invalidate the signature that proves the capture is unmodified; keeping them in a separate file means the UI opens `audit.db` read-only. The sidecar is attached as schema `sup` on every read connection, and the views that read it — `v_grid_findings`, `v_export_findings_evidence`, `dim_asset_tier`, and `v_grid_escalation_paths` — are created per connection as temp views, because SQLite forbids a stored view from referencing an attached database.

`dim_sidecar_meta` records the originating run's identity — run id, forest, domain, assessment mode, scope, coverage id, and tool version — written once when the sidecar is created and never rewritten. A sidecar is a file and can be copied away from its bundle, so this is what lets an import check that acceptances came from a run of the same scope. `ProfileId` is not among the fields because it is not stored in `audit.db`; it is derived from mode, domain, and scope, all three of which are recorded here.

`dim_sidecar_meta.coverage_id` is a copy of `run.coverage_id`, and the copy is the point: the acceptance import gate reads the *sidecar's* stamped identity, not the bundle's `run` table, so a coverage identity that lived only in `audit.db` would read as `NULL` for every import and refuse everything. It carries the same meaning as the original, including that `NULL` means *cannot be established* and never matches another `NULL`.

### Asset tiers are split by source

A tier is two different kinds of thing. Rows the classifier derives are capture evidence and stay in `audit.db` under the signature. Rows a user sets are a policy statement about the organisation, so they live in the sidecar as `dim_asset_tier_policy`.

Consumers never join the two. A temp view named `dim_asset_tier` is created on every read connection and resolves precedence — policy over derived — so a query reads the single name and gets the effective tier. In SQLite a temp view outranks a table of the same name, which is what makes the split invisible to readers.

Two consequences worth stating, because both are relied upon:

- **A view stored in `main` does not see the temp view.** Its body binds to `main`. That is why `v_grid_escalation_paths` is recreated as a temp view on read connections, and why `EscalationPathRuleEvaluator` — which decides *which findings exist* — deliberately says `main.dim_asset_tier`. A run is immutable evidence: a policy tier must not retroactively change what a signed snapshot found.
- **Re-analysis cannot reach policy tiers.** `ResetForReanalysis` deletes from `main`, so hand-curated tiers survive it.

### Tier 0 is decided on three dimensions, from one place

An object is Tier 0 if **any** of three things is true of it, and the three are not interchangeable:

| Dimension | Tier-0 values |
|---|---|
| Well-known RID, or a well-known SID | the RIDs in `Tier0RidCatalog`; `S-1-5-18`, `S-1-5-19`, `S-1-5-20` |
| Object class | `domainDNS`, `nTDSDSA`, `trustedDomain` |
| DN pattern | `CN=AdminSDHolder,…`, `OU=Domain Controllers,…`, the domain root |

`StaticAssetTierClassifier` owns all three, and `IAssetTierClassifier.Classify(sid, dn, objectClass)` is the only correct way to ask the combined question: it takes the strongest of the three answers. `ClassifySid` alone answers a *narrower* question and must not be used to decide whether an object is Tier 0.

The distinction matters most for the objects that have no well-known RID at all. **A domain root object's SID *is* the domain SID** — `S-1-5-21-2577669926-2442307531-374132434`, with no trailing well-known RID — so no RID test can identify it, and it is the single most privileged object in the domain. `AdminSDHolder` and the Domain Controllers OU have no SID whatsoever.

Consequently a query must never decide Tier-0 membership with a SID pattern such as `o.sid LIKE '%-512'`. Where a query needs the set, `Tier0ObjectTable` materialises it into `temp.tier0_object` by asking the classifier, and the query joins that; `AssetTierWriter` asks the classifier directly per row. These are the only two places the question is answered.

## Dimension Tables

| Table | Purpose |
|---|---|
| `dim_object` | All captured AD objects (users, computers, groups, OUs, GPOs, etc.) |
| `dim_principal` | Resolved principal identities (SID → display name, kind, domain) |
| `dim_guid_map` | GUID-to-name mapping for schema attributes and extended rights |
| `dim_database_metadata` | Key-value metadata about the database and the run that produced it — see below |
| `dim_delegation` | Delegation and AdminCount annotations per object |
| `dim_gpo_setting` | Group Policy settings captured from SYSVOL (Registry.pol, security templates) |
| `dim_asset_tier` | Derived tier classification (Tier 0, Tier 1, Custom) per SID. Capture evidence. Also the name of the temp view that resolves policy over derived — see above |
| `dim_asset_tier_policy` | User-set tier overrides per SID. Stored in the sidecar, not `audit.db` — see above |
| `dim_object_note` | User-added notes on objects |
| `dim_trust` | Forest/domain trust relationships |
| `dim_password_policy` | Fine-grained password policies |
| `dim_suppression` | Finding suppression (accepted risk) records. Stored in the sidecar, not `audit.db` — see below |
| `dim_sidecar_meta` | Identity of the run a suppression sidecar was created for. Sidecar only; single row |
| `dim_unresolved_group_member` | Group members that could not be resolved to a SID. `reason_category` classifies each against the *discovered* forest — `InForestNotCaptured`, `CrossForest`, `CapturedDomainDnMissing`, or `Undetermined` — and is the value consumers must read; `reason` is display prose. Carries two domains: `domain_fqdn` is the containing group's, `member_domain_fqdn` the member's own (`NULL` when undecidable from the DN) |
| `dim_run` | Saved audit run metadata (name, notes, baseline flag) |

### `dim_database_metadata`

A flat key-value table describing the database and the run that produced it. Several capture and
analysis paths write to it, in these families.

**Run identity**, written by `DirectCaptureRunner.Merge.cs` as the capture merges: `run_id`,
`assessment_mode`, `schema_version`, `forest_fqdn`, `domain_count`, `object_count`, `ace_count`,
`capture_method`, `completed_utc`.

`assessment_mode` is always `Security`, in this key and in the `run` table's column of the same
name. It records what kind of capture produced the bundle, and the product performs one kind, so a
reader may treat it as a constant: it is not a dimension anything varies along, and it is not shown
to a user. A bundle whose `assessment_mode` cannot be read is a Security capture whose metadata read
failed — never a capture of some other kind — and readers default it accordingly rather than
withholding anything from the run. See
[decision 0007](decisions/0007-the-product-surfaces-no-assessment-mode.md).

**Capture scope and filtering**, written by the same path: `audit_scope`, `capture_filter_mode`,
`capture_filter_catalog_version`, `capture_filter_description`, `comprehensive_capture_enabled`,
`ou_exclusions`, `ou_exclusions_applied`, `ou_exclusions_count`.

**Preflight and re-analysis provenance**: `forest_dc_preflight`, and on the re-analysis path
`analysis_source_captured_utc`.

**Delegation bundle pack identity**: `bundle_pack_id`, `bundle_pack_version`, `bundle_count`.

**Derived analysis metrics**, written by the control-edge, escalation-path and chokepoint
services: roughly forty keys prefixed `control_edges_`, `escalation_path_`, `escalation_paths_`
and `escalation_chokepoints_`, carrying counts, budgets and durations for those phases.

**Pipeline phase results**, written by the derived analysis pipeline as it runs. Every one of
these keys begins `pipeline_phase_`, and the phase name is lowercased with spaces replaced by
underscores — `pipeline_phase_create_views`, `pipeline_phase_control_edges`. Each value is a
status with the phase duration appended: `OK (1204ms)`, or `FAILED: <exception message> (91ms)`.

Writes to this table are best-effort. The pipeline swallows a failure to record a phase rather
than aborting the run over it, so a key can be missing even though its phase ran.

A phase key is read three ways, and an absent one is not the healthy reading:

| Value | Meaning |
|---|---|
| `OK (<n>ms)` | The phase ran and completed. |
| `FAILED: <message> (<n>ms)` | The phase ran and threw. |
| *absent, empty, or in neither shape* | **Unrecorded** — the phase did not run, or its outcome could not be written. |

**These keys are what a reader consults before stating a derived number.** A count over derived
output means nothing unless every phase behind it recorded `OK`, and there are two ways for that to
go wrong that look nothing alike: a missing view makes the query throw, while a view over a table
no phase populated makes the query succeed and return a truthful zero. Only the phase verdict tells
either apart from a forest that genuinely contains nothing, which is why a reader keys off these
keys rather than probing for the view.

**Which phases stand behind a count depends on where the count's data comes from, and the set is
usually smaller than the pipeline.** A count is trustworthy once every phase that had a hand in
producing it recorded `OK`; naming more phases than that withholds numbers the run can still stand
behind. Three shapes occur:

| The count is over | Phases behind it |
|---|---|
| Facts written during capture, exposed through a view | `Create views` only |
| The output of one derived phase | `Create views` plus that phase |
| Derived output that reads other derived tables | `Create views` plus every phase it reads from |

`dim_delegation` is the first shape: it is written during capture and no derived phase populates
it, so once `v_grid_delegations` exists a delegation count means what it says. A findings count is
the third — rule evaluation reads `fact_control_edge` and `fact_escalation_path`, so a findings
total computed after either of those phases failed is a smaller number than the forest warrants,
arrived at without error.

A shortfall in what capture reached is a different question, answered separately by the run's
coverage state rather than by these keys.

> **This list is not exhaustive, and cannot currently be made so cheaply.**
> `SecureAD.Core.Evidence.MetadataKeys` declares itself the canonical set of key names, and holds
> 24. Roughly forty-six further keys are written as string literals at their call sites and never
> pass through it. Until every write goes through `MetadataKeys`, a reader looking for the
> complete set must read the writers, and no test can enforce this section against the code.

#### `pipeline_phase_derived_health`

The pipeline's aggregate verdict on its own output, written as the last act of the derived
analysis run. It is the answer to "can this bundle's derived analysis be trusted to be
complete", and it is the only place that question is answered.

| Value | Meaning |
|---|---|
| `Complete (<n>ms)` | Every derived phase succeeded. |
| `Degraded: <phase>, <phase> (<n>ms)` | At least one phase failed, and the value names which. |
| *absent, empty, or in neither shape* | **Unrecorded.** |

**Unrecorded is not healthy.** It means the pipeline either never reached the line that writes
the verdict, or could not write it. Either way the run has not stated that its analysis finished,
and not stating that it finished is not the same as stating that it did — so Unrecorded is
treated as at least as serious as Degraded everywhere it is read. It is also not an old bundle:
nothing predates the current build (see [decision 0001](decisions/0001-no-backward-compatibility.md)).

**This is not the run's lifecycle state.** A degraded run is still `Sealed`; its health is carried
on a separate axis. See [`CAPTURE-PIPELINE.md`](CAPTURE-PIPELINE.md) for the three axes.


A parallel key, `pipeline_phase_findings_health`, carries the same three-way verdict for the
findings phases, which run separately after coverage rows are finalised.

### Every bundle carries the whole schema

Opening a derived database creates the base tables **and** the security tables, unconditionally,
whether or not the run will populate them. A bundle therefore always has the full set of tables.

The consequence matters more than the fact: **the presence of a table carries no information**,
and a reader must never infer from `TableExists` that a run captured or derived something. An
empty table means the query found no rows, and nothing more. What a run actually achieved is
recorded — in `run_coverage` and `fact_coverage` for capture, and in
`pipeline_phase_derived_health` for derived analysis — and those are the values to read.

## Fact Tables

| Table | Purpose |
|---|---|
| `fact_ace` | Explicit ACEs from captured DACLs, used for analytics, findings, control edges, delegation analysis, and explicit drift |
| `fact_sysvol_ace` | Security descriptors (DACLs) of GPO folders captured from SYSVOL |
| `fact_object_acl_materialized` | Compressed applied/materialized DACL payload per object for object-detail permissions and full live ACL comparison |
| `fact_coverage` | Per-module, per-domain coverage completion status |
| `fact_principal_resolution_status` | Resolution status per SID |
| `fact_group_membership_direct` | Direct group membership edges |
| `fact_group_membership_closure` | Transitive group membership with depth |
| `fact_expansion_status` | Group expansion completion status |
| `fact_control_edge` | Derived control relationships (principal → object) |
| `fact_escalation_path` | Multi-hop escalation paths to high-value targets |
| `fact_escalation_chokepoint` | Chokepoint nodes shared across many escalation paths |
| `fact_finding` | Automated security findings with severity and evidence |
| `fact_delegation_bundle_match` | Delegation bundle match results |
| `fact_merge_conflict` | Merge conflicts from multi-domain capture |
| `fact_sid_history` | SID history entries |

## Run Tracking Tables

The offline run-library metadata lives in `dim_run` (above). Per-run execution state uses:

| Table | Purpose |
|---|---|
| `run` | Current run metadata (ID, state, timestamps, counts) |
| `run_phase` | Pipeline phase execution log with timing |
| `run_checkpoint` | Resume checkpoints for interrupted captures |
| `run_coverage` | Per-module coverage status for the current run |
| `run_domain_discovered` | The forest's full domain list as discovery found it — the denominator completeness is measured against |
| `run_domain_declaration` | Per-domain reason the run included or excluded it (`Included`, `ExcludedByUser`, `ExcludedUnreachable`), plus the attestation covering an exclusion and the outcome of verifying it |

`run_coverage` records what capture *achieved*, per module per shard. `run_domain_discovered`
records what the forest *contains*. The two are deliberately separate: completeness is
"covered ⊆ discovered", so deriving the discovered set from the captured one would measure the
evidence against itself. `run.discovery_confidence` carries discovery's own verdict and defaults to
`NotValidated`, so a run that never established forest completeness reads as "not known" rather
than as clean.

`run.coverage_id` is the identity of the evidence the run *declared* it would gather — forest root,
declared domain set and OU exclusion profile, hashed. It answers "same evidence", which is what
gates compare and acceptance import; `dim_run`'s profile identity answers "same target", which only
groups the library. It hashes the **declared** set, not the achieved one, so a DC dying mid-run does
not strand that run in its own permanent comparison island — whether the declaration was *achieved*
is the separate coverage axis, derived from `fact_coverage`.

Unlike `discovery_confidence` it is **nullable with no default**. A re-analysis of a saved capture
declares nothing, and deriving an identity from the capture being re-read is the same circularity
`run_domain_discovered` exists to prevent. `NULL` therefore means *cannot be established*, and is
distinct from — never conflated with — an empty declaration.

`run.tool_version` identifies the **build**, as `major.minor.patch+commitSha` — for example `3.0.0+40debb2afd6976ed3382d2f80a311825ceec7d6f`. It comes from `ToolVersion.Current`, which reads the assembly's informational version; `<Version>` is set in `Directory.Build.props` and the SDK appends the commit sha. Two captures from different commits therefore carry different strings, and a bundle names the code that produced it.

Only the **major** component is compared, via `ToolVersion.ParseMajor` in `CompareCompatibilityValidator`. The appended sha is ignored there, so two builds of one release never look incompatible.

This matters because every comparison across time — compare, baseline eligibility, the acceptance sidecars — otherwise assumes that findings which differ mean the **forest** differed. When the rules themselves change, the sha is what distinguishes "the environment improved" from "the analysis changed".

There is no fallback if the attribute is missing: a build that cannot state its own identity is a broken build, not a `0.0.0` one.

### Exclusion attestations

A run covers the whole enumerated forest; a domain may be excluded only as an attested exception.
`run_domain_declaration` carries four columns for this, and they answer four different questions:

| Column | Question | Notes |
|---|---|---|
| `declaration_reason` | Why was it excluded? | Mechanical fact. `Included`, `ExcludedByUser`, `ExcludedUnreachable` |
| `exclusion_attestation` | What did a human claim about it? | `AttestedEmpty` or `AttestedDegraded`. `NULL` exactly when `Included` |
| `attestation_contradicted` | Did the captured data falsify the claim? | Set post-capture; only an `AttestedEmpty` claim is falsifiable |
| `contradicting_member_count` | How wrong was it? | The evidence — unresolved members belonging to the domain |

**The reason and the attestation are deliberately separate.** A domain can be `ExcludedUnreachable`
*and* attested degraded; folding a mechanical fact and a human claim into one enum loses that pair.

**A contradicted claim is recorded beside the claim, never over it.** What the user asserted and what
turned out to be true are different facts, and rewriting `exclusion_attestation` would erase the
accountability the attestation exists to create. Consumers deciding whether a run may serve as a
baseline must therefore read the *effective* posture — a contradicted `AttestedEmpty` is
`AttestedDegraded` — rather than the stored claim.

`AttestedEmpty` is verified after capture against `dim_unresolved_group_member` rows whose
`reason_category` is `InForestNotCaptured`; any such row whose **member** belongs to the excluded
domain falsifies the claim. `AttestedDegraded` asserts nothing falsifiable and is never a baseline.

**Which domain is matched, and why the distinction is load-bearing.** That table carries two
domains per row and they answer different questions. `domain_fqdn` is the domain of the *group*
that contains the member — the capture domain the membership was read from, which is what coverage
attribution joins on. `member_domain_fqdn` is the domain the *member* belongs to, derived from
`member_dn` at capture, and is `NULL` when no domain can be derived from that DN. The verification
matches on `member_domain_fqdn`, because that is the domain an exclusion attestation speaks about.
The two differ in exactly the case the check exists for: a captured group holding a member in an
uncaptured domain. Matching on the group's domain instead means the excluded domain is never a key
in the result, so no claim of emptiness can ever be contradicted and the check passes vacuously for
every forest.

Note that `run_domain_declaration.domain_fqdn` is lowercased on write while
`dim_unresolved_group_member.member_domain_fqdn` keeps its captured casing, so the two must be
matched case-insensitively.

Full reasoning, including why a coverage gate could not do this job, is in `docs/work/RUN-MODEL-DESIGN.md`
Part 5.

### An unread table is not an empty one

`fact_coverage` and `run_domain_declaration` are both in the base table set, so they exist in every
bundle (see `INVARIANTS.md` I-6). A run that recorded nothing has an empty table, which reads
cleanly and returns no rows. Three states therefore have to stay apart, and the middle one is the
reason the outer two cannot share an answer:

| State | Means | Consequence |
|---|---|---|
| Populated | The run recorded what it covered or declared | Read normally |
| Empty, readable | The run recorded nothing — a re-analysis of a saved capture declares nothing | A coherent answer, and not a defect |
| Unreadable | The query failed | Nothing was established; no conclusion may rest on the absence |

Readers of these tables report whether the read succeeded alongside what it returned, because the
two degrade in opposite directions. An unread declaration set looks like *no exclusions*, which makes
a run look like a full-forest capture and would qualify it as a baseline. An unread coverage set
looks like *nothing covered*, which makes the absence of a finding look like evidence the finding is
gone. Both are the direction that claims more than the run earned, which is why neither is allowed to
present as an empty result.

The coverage axis itself is withheld the same way: when the covered set cannot be read, coverage
resolves to `Unknown` rather than being computed from an empty numerator, which would otherwise
answer `Partial` — a claim that some of the forest was covered, made from a query that established
nothing.

## Grid Views (v_grid_*)

All UI grids read from these views. They join dimension and fact tables to produce display-ready rows with pre-resolved names.

| View | Source tables | UI Tab |
|---|---|---|
| `v_grid_objects` | dim_object | Objects (All) |
| `v_grid_owners` | dim_object | Objects (Owners) |
| `v_grid_adminsdholder` | dim_object + dim_delegation | Objects (AdminSDHolder) |
| `v_grid_stale_dormant` | dim_object | Objects (Stale/Dormant) |
| `v_grid_ace_facts` | fact_ace + dim_object + dim_principal | ACEs |
| `v_grid_delegations` | dim_delegation + dim_object | Delegations |
| `v_grid_delegation_summary` | dim_delegation + dim_object | Delegation Summary |
| `v_grid_delegation_bundles` | fact_delegation_bundle_match | Delegation Bundles |
| `v_grid_group_membership` | fact_group_membership_direct + dim_principal | Group Membership |
| `v_grid_group_expansion` | fact_group_membership_closure | Group Expansion |
| `v_grid_laps_status` | dim_object + dim_delegation | LAPS Status (No-LAPS) |
| `v_grid_coverage` | fact_coverage | Coverage |
| `v_grid_principals` | dim_principal | Principals |
| `v_grid_principals_enriched` | dim_principal + aggregates | Principals (enriched) |
| `v_grid_kerberos_auth` | dim_delegation + dim_object | Kerberos Auth |
| `v_grid_findings` | fact_finding + dim_principal + dim_object | Findings |
| `v_grid_control_edges` | fact_control_edge + dim_object + dim_principal | Control Edges |
| `v_grid_escalation_paths` | fact_escalation_path + dim_object + dim_principal | Escalation Paths |
| `v_grid_high_value_targets` | dim_object + dim_asset_tier | High Value Targets (Tier 0) |
| `v_grid_sid_history` | fact_sid_history + dim_object | SID History |
| `v_grid_trusts` | dim_trust | Trusts |
| `v_grid_password_policies` | dim_password_policy | Password Policies |
| `v_grid_unresolved_members` | dim_unresolved_group_member | Unresolved Members |
| `v_grid_merge_conflicts` | fact_merge_conflict | Merge Conflicts |

### Support and export views

These views back other views, enriched queries, or exports rather than a single UI grid tab:

| View | Purpose |
|---|---|
| `v_grid_objects_rich` | Objects enriched with aggregate flags, used by object-centric queries |
| `v_group_membership_effective` | Effective (direct + transitive) membership used by other views |
| `v_export_findings_evidence` | Flattened findings + evidence rows for export |
| `dim_asset_tier` | Temp view resolving tier precedence, policy over derived. Shares the name of the derived table it shadows, so every consumer reads one name — see "Asset tiers are split by source" above |

### What an absent view means

Views are created by a single phase of the derived analysis pipeline. That phase can fail, and
the rest of the pipeline continues without it, so a bundle can be missing some or all of its
`v_grid_*` views.

**An absent view is a fact about the capture. It is never a fact about the forest.** A reader
that finds `v_grid_escalation_paths` missing has learned that this run's analysis did not
finish — not that the directory contains no escalation paths. Rendering the second as the first
is the failure mode this rule exists to prevent: in a security audit tool, "nothing found" and
"the search did not run" are the same reassuring empty grid, and only one of them is safe to act
on.

So readers do not probe for individual views to decide whether data is trustworthy. The run
records its own completeness once, in `pipeline_phase_derived_health`, together with the reason —
and that is what is read. A degraded bundle can then say *which* phase failed instead of
displaying an empty section. See
[decision 0002](decisions/0002-absent-view-means-degraded-run.md).

## Key Relationships

```
dim_object.object_guid ←→ fact_ace.object_guid
dim_object.sid         ←→ dim_principal.sid
fact_ace.trustee_sid   ←→ dim_principal.sid
fact_control_edge.source_sid         → dim_principal.sid
fact_control_edge.target_object_guid → dim_object.object_guid
fact_escalation_path.source_sid      → dim_principal.sid
fact_escalation_path.target_sid      → dim_principal.sid
fact_finding.target_id               → dim_object.object_guid
fact_finding.source_edge_id          → fact_control_edge.edge_id
fact_finding.source_path_id          → fact_escalation_path.path_id
```
