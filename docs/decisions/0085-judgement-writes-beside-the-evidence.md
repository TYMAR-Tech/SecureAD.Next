# 0085 - Judgement writes beside the evidence, not into it

Date: 2026-08-25
Status: Accepted. The owner's condition on acceptance was that it must not add materially to the
time of an audit, and it does not: capture is untouched, and the projection below is optional -
loading the graph into memory as the predecessor's `LoadControlGraphAsync` did costs nothing extra.
Persisting it is an optimisation to be taken only if reopening a judged bundle proves slow.

Sits under [0030](0030-the-product-produces-sealed-evidence-never-signed.md). Extends to what the
*product* concludes the rule already applied to what the *customer* writes: `BundleLayout` keeps
annotations in their own file because "an acceptance written into the evidence would invalidate the
seal that proves the evidence is unmodified", and names that separation as what makes
[0015](0015-a-bundle-names-a-pattern-it-never-explains-one-away.md) and
[0052](0052-the-domain-is-the-only-unit-of-scope.md) enforceable rather than promised. This record
also resolves a contradiction in the current schema.

## Context

The judgement half has to put its findings, routes and remediation evidence somewhere. Three
options were on the table, and the question was raised because the predecessor answered it
differently.

**The predecessor sealed once, at the end, over everything.** `DatabaseIntegrityService.Sign` ran
after capture *and* after the whole derived pipeline, so evidence and conclusions carried one
signature. Re-analysis copied the file, re-ran the pipeline and issued a **fresh** signature - the
service's own remarks worry about "vouching for evidence no build ever vouched for". A verified
signature therefore meant *unchanged since we last wrote to it*, not *this is what the directory
said*.

**This product already seals earlier.** `BundleWriter.Complete` seals `evidence.db` at the end of
capture, before any rule has run. The judgement spec assumes the same shape and goes further,
stating that "the run is sealed separately once every scheduled rule has finished" - a
`JudgementRun` with its own states.

**The schema contradicted that, and no longer does.** `BundleSchema` carried `finding` and
`evaluated_rule` tables inside the sealed evidence, added at schema version 6. Nothing in production
wrote them: `WriteFinding` and `WriteEvaluatedRule` were called only by `FindingStorageTests`. So
the contradiction was cheap to resolve, and it was resolved on 2026-08-25 as stage 1 of the roadmap
— the three tables and the code serving them are gone, and `BundleSchema.Version` stands at 8.

**Indexing is the reason this looked like a hard call.** The predecessor carried 55 indexes and
getting them right was real work, so a design that forbids adding indexes later reads as a
regression. Counted by table, it is not:

| Table | Indexes | Captured or derived |
|---|---|---|
| `fact_control_edge` | 7 | derived |
| `fact_delegation_bundle_match` | 3 | derived |
| `fact_group_membership_direct` / `_closure` | 4 | derived |
| `dim_delegation` | 2 | derived |
| `fact_escalation_path` / `_chokepoint` | 2 | derived |
| run bookkeeping | ~10 | derived |
| `dim_object` | 7 | captured |
| `fact_ace` | 2 | captured |

**Forty-odd of the fifty-five are on tables the analysis itself produced.** They index data the
directory never supplied, and nothing about sealing the evidence touches them.

## Decision

**A run is three artefacts. The seal boundary sits after capture and does not move.**

| File | Written by | Sealed | Disposable |
|---|---|---|---|
| `evidence.db` | capture | yes, once, and never re-sealed | no |
| the judgement store | a judgement run | sealed separately, per its own run | **yes** |
| `annotations.db` | the customer | no | no |

Three consequences follow, and they are the point of the record.

**1. The evidence fingerprint is taken once and is permanent.** Re-judging a bundle under a better
rule catalogue cannot alter it, so the product can still say *this is what the directory said* about
a bundle judged many times. The predecessor could not.

**2. The judgement store is rebuildable, and that is a feature rather than a tolerance.** If an
index is wrong, or a projection turns out to be the wrong shape, the file is deleted and the bundle
re-judged. The predecessor could never do this: judgement and evidence shared one file, so
rebuilding the analysis rewrote the evidence and destroyed its signature. **This design has more
indexing freedom than the predecessor, not less.**

**3. Findings move out of the sealed schema.** `finding` and `evaluated_rule` belong to the
judgement store. Leaving them in `evidence.db` would put findings in two places, and would mean a
rule catalogue improvement either cannot be applied to an existing bundle or re-seals the evidence
to apply it.

**Evidence is indexed for capture and browsing only. Judgement indexes its own store.**

Where judgement needs a lookup the evidence does not serve - object by SID, the reverse membership
map, object by `sAMAccountName` - it reads the evidence once and writes an indexed projection into
its own store. The per-attribute value tables are keyed `(object_id, ordinal)` with values
deliberately unindexed, so this is not an omission being worked around; it is the browsing schema
being used for a different question.

This is what the predecessor did anyway. `EscalationPathService.LoadControlGraphAsync` built exactly
such a projection in memory before walking it. The only change is that it is persisted in a file the
product owns rather than materialised into the evidence database.

## Consequences

**Costs, stated plainly.**

- Disk. Some evidence columns are duplicated into the judgement store as projections.
- One sequential pass over the evidence at judge time to build them.
- Two seals to verify and two run states to present. An operator can now see `Verified` evidence
  under a `CompletedDegraded` judgement, and the shell has to say what that means. The predecessor
  had one answer because it had one artefact.
- An index that judgement needs on the *evidence* still cannot be added to bundles already captured.
  The projection is the answer, not a retrofit.

**What this does not decide.**

- Whether the judgement store is one file per bundle or one per judgement run.
- What an operator is shown when the two seals disagree.
- Whether a judged result is a record of what was concluded then, or is recomputed on open. The
  spec's determinism criteria lean toward *record*; nothing has ruled.
- `P-93` - what an acceptance attaches to - is adjacent and still open.

## Alternative rejected

**Seal after findings, as the predecessor did.** Rejected because it hands back the constraint that
made the predecessor's indexing rigid, and because it destroys the permanent evidence fingerprint -
the strongest claim this product makes. It buys nothing that the projection does not already give.
