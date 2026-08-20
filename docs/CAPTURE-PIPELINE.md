# The capture pipeline

How a capture runs end to end: the phases, how failure is handled, and what the resulting bundle
records about its own completeness.

This describes the pipeline as it is, and is updated whenever the pipeline changes. A dated code
trace of one path through the capture, taken at commit `86faac88`, was previously an appendix here
and now lives in `archive-1/CAPTURE-PIPELINE-TRACE-2026-08-03.md`. It is unmaintained and contains
at least one claim that is no longer true.

---

## Derived analysis: phases, failure, and degraded runs

After capture has written objects, ACEs, principals and group memberships into the database, the
derived analysis pipeline runs in phases, in order.

Each phase records its own outcome under the metadata key below, which is the phase name
lowercased with spaces replaced by underscores. These names are the ones the run writes and every
reader matches on, so they are given here exactly rather than described:

| # | Phase | Metadata key |
|---|---|---|
| 1 | `ANALYZE` | `pipeline_phase_analyze` |
| 2 | `Create views` | `pipeline_phase_create_views` |
| 3 | `GUID map` | `pipeline_phase_guid_map` |
| 4 | `Delegation bundle matches` | `pipeline_phase_delegation_bundle_matches` |
| 5 | `Group expansion` | `pipeline_phase_group_expansion` |
| 6 | `Control edges` | `pipeline_phase_control_edges` |
| 7 | `Asset tier classification` | `pipeline_phase_asset_tier_classification` |
| 8 | `Escalation paths` | `pipeline_phase_escalation_paths` |
| 9 | `Escalation chokepoints` | `pipeline_phase_escalation_chokepoints` |

`Findings` (`pipeline_phase_findings`) and `Backfill finding principals`
(`pipeline_phase_backfill_finding_principals`) run as a separate, later pass, once coverage rows
have been finalised. Their aggregate verdict is `pipeline_phase_findings_health`, not
`pipeline_phase_derived_health`, because the two passes seal independently.

### `dim_asset_tier` is written at the end of phase 7, not at its start

Phase 7 does two things in order: it *builds* a classifier, then it *applies* it. The derived
classifier's own queries — transitive Tier-0 membership, DCSync holders, dangerous control over a
Tier-0 object — run while it is being built, which is **before** any row of `dim_asset_tier`
exists. That table is phase 7's output, not its input.

So a phase-7 component cannot read `dim_asset_tier`, and must ask an `IAssetTierClassifier` for any
tier question instead. From phase 8 onward the table is populated and can be read — but a component
that needs the same answer as phase 7 asks the classifier too, so that the two cannot diverge.

### Phases fail individually, and the pipeline continues

Each phase runs inside its own exception boundary. If a phase throws, the pipeline **records the
failure and moves on to the next phase** rather than aborting. A cancellation is different: it is
not caught, and it stops the run.

This is deliberate. A failure in escalation path derivation should not cost the operator the
control edges and findings that had already been computed, which for a large forest can represent
hours of capture. The cost of that choice is that a bundle can be internally incomplete, so the
pipeline is obliged to say so.

Every phase writes its own outcome into `dim_database_metadata` under a `pipeline_phase_*` key,
as `OK (<n>ms)` or `FAILED: <message> (<n>ms)`. When all phases have run, the pipeline seals an
aggregate verdict into `pipeline_phase_derived_health`:

- **`Complete`** when no phase failed.
- **`Degraded: <phase>, <phase>`** when any did, naming each failed phase.

That verdict is the run's own statement about whether its derived output can be trusted, and it
is what every consumer reads.

### A count the run cannot vouch for renders as unknown

An exported artefact never states a derived count unless every phase behind that count recorded
`OK`. Where it cannot, the count is rendered as the word **unknown**, in the slot the number would
have occupied, naming the phase responsible — *"Findings: unknown — the Control edges phase did not
complete."*

This is decided per count. A run that lost escalation path derivation still knows how many control
edges it built, and that number still prints; withholding a whole summary because one phase failed
would cost the reader evidence the run does hold. The word occupies the number's place so its
absence is visible to someone skimming, which a blank or a dash would not be.

The counts depend on more phases than their own. Findings are not self-contained: rule evaluation
reads `fact_control_edge` and `fact_escalation_path`, so a findings total computed after either of
those phases failed is a smaller number than the forest warrants, arrived at without any error. A
count is withheld when any phase it draws on is not `OK`.

The report is still generated. Re-analysis refuses an incomplete source because it ends by signing
new evidence; a report only renders evidence that already exists, and partial evidence is still
worth reading.

### The grid says why its risk columns are gone

The objects grid reads risk-bearing columns from a view the create-views phase builds. On a run
whose analysis did not finish it falls back to the base columns, and it states the reason on the
page rather than simply presenting a narrower grid. A degraded run and a forest with nothing to
report must never render alike, and a missing column is exactly the kind of absence a user reads as
a fact about the directory.

Recording is best-effort — a failure to write a phase row is swallowed rather than allowed to
abort the run — so the verdict can also be **absent**. An absent verdict is treated as at least as
serious as a degraded one. See [`DATA-MODEL.md`](DATA-MODEL.md) for the three states and their
exact stored form.

### A run is described by three independent axes

A degraded run is **not** a different kind of run state. Completeness and lifecycle are separate
questions, and the run model keeps them separate:

| Axis | Question it answers | Values |
|---|---|---|
| `RunState` | Did the run finish and commit? | `Draft`, `Capturing`, `Merging`, `Finalizing`, `Sealed`, `Failed`, `Corrupt` |
| `RunCoverage` | How much of the forest did it manage to capture? | `Full`, `Partial`, `Unknown` |
| `AnalysisHealth` | Did derived analysis finish? | `Healthy`, `Degraded` |

A capture that completes seals as `RunState.Sealed` **regardless of how it went**. A pipeline
failure sets `AnalysisHealth.Degraded`; domains lost during capture set `RunCoverage.Partial`.
Neither changes the lifecycle state, because in both cases the run did finish and commit — the
question `RunState` answers.

`RunState.Partial` and `RunState.Degraded` used to exist and were deliberately removed. They were
never alternatives to `Sealed` — a partial run is sealed, and a degraded run is sealed — so
holding them on the lifecycle axis forced every reader that wanted to know "did this finish?" to
reconstruct the answer from an `or` chain across values that were not mutually exclusive.

The practical consequence for a reader: **do not infer completeness from `RunState`.** `Sealed`
means committed, not good. To ask whether the evidence is whole, read `RunCoverage`; to ask
whether the analysis over it is whole, read `AnalysisHealth`.

The types themselves, which component decides each axis, and which of them are stored rather than
recomputed on read, are in [`ARCHITECTURE.md`](ARCHITECTURE.md#the-run-model).

### View creation is untransacted, so partial creation is reachable

The create-views phase drops every existing view, then executes the base view DDL statements
followed by the security view DDL statements, one statement at a time. **The loops are not wrapped
in a transaction.** Each `CREATE VIEW` commits on its own.

The consequence is that a failure partway through leaves the database with the views created
before the failure and without those after it. There is no rollback to the previous set, and no
intermediate state in which the old views survive: the drop has already happened. A bundle can
therefore hold a genuinely partial set of views.

This is safe only because the phase's failure is recorded. Nothing infers completeness by probing
for a view; the recorded verdict is read instead. A reader that checked for one view would be
sampling a set that is not all-or-nothing, and would draw a conclusion about the whole from
whichever view it happened to pick.

### Every view DDL is `CREATE VIEW IF NOT EXISTS`

Because the phase drops all existing views before recreating them, `IF NOT EXISTS` never guards
against a view left over from a previous run. What it does guard against is a name collision
*within the same run*: if two DDL statements in the schema define the same view name, the second
one silently does nothing, and the view keeps the first definition.

That failure is silent by construction. It raises no error, fails no phase, and leaves
`derived_health` reading `Complete` — the run is complete, because every statement it executed
succeeded. The database is simply not the shape the schema describes.

So a duplicate view name in the schema is caught by review and by tests, and not at runtime. When
adding a view, the name is the thing to check.
