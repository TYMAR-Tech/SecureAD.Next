# S-22 — What the old application does with the data

## Scope

This session reads the **analytical half** of the previous product — everything that happens *after*
capture and storage — and asks two questions of it: *is this the right shape*, and *is what it claims
about itself true?*

**Branches D, E and G.** Derived analysis, rules and findings, and comparison. Branches I and J
(output and presentation) are read only as **evidence of what the analysis was for**, never as
subjects in their own right.

It produces a **ranked list of design challenges** with the evidence for each, written to
`docs/next/S-22-[slug].md`. **It changes no code, decides nothing, and rebuilds nothing.**

**Why this half, and why now.** Branches A, B and C were read on 2026-08-12 and the reading is
recorded in [`S-20`](../../history/S-20-what-a-bundle-stores.md), including an explicit list of what was *not*
read. What was not read is this: the rules engine, `DerivedAnalysisPipeline`, `EscalationPathService`,
compare, and the tier classifiers. Every statement made about those so far in this rebuild has been
**read off the schema they write, not off their code** — and that is stated in `S-20` as a limitation
rather than hidden.

**That limitation has already produced one wrong conclusion and one real finding.** `F-S20-14` records
that the predecessor's escalation graph never modelled containment: a principal granted control over
a container produced one edge to the container and none to the thousands of objects beneath it, so
paths, `affected_path_count` and Tier 0 reachability were all computed from a graph missing most of
its edges. It was found by reading four files after someone asked *why* a decision had been made —
not by any test, and not by the map. **This session is the systematic version of that question.**

**Out of scope:** implementing anything; the rule catalogue's *contents*, which is a product question
and a different exercise; and branches A, B, C, F, H and K, which are either read, deleted or
dispositioned.

## Read first

In order:

- [`docs/next/README.md`](../README.md) — §`Tests`, §`Gates`, §`How to continue this work` and
  §`Status`
- [`DESIGN-challenges-to-the-inherited-shape.md`](../../history/DESIGN-challenges-to-the-inherited-shape.md) —
  five challenges, of which **challenge 1 is squarely in this session's scope** and challenges 3, 4
  and 5 are explicitly labelled opinion drawn from reading the schema rather than the code. This
  session is where they are confirmed, refuted or extended
- [`S-20`](../../history/S-20-what-a-bundle-stores.md) — its *What was read, and what was not* section, then
  `F-S20-9`, `F-S20-14` and `F-S20-15`. The last is an obligation this session inherits: storing
  inherited entries means derivation must suppress expected grants or the graph fills with edges from
  `Domain Admins` and `SYSTEM`, and **D7 owes that**
- [`docs/next/POINT-IN-TIME-REVIEW.md`](../../history/POINT-IN-TIME-REVIEW.md) — what each record decided
- [`docs/map/D-derive-and-analyse.md`](../../map/D-derive-and-analyse.md),
  [`E-rules.md`](../../map/E-rules.md), [`E-findings.md`](../../map/E-findings.md) and
  [`G-compare.md`](../../map/G-compare.md) — the inventory. Per
  [`0033`](../../decisions/0033-nothing-inherited-is-definitive.md) it names the file to open and is
  **not** the evidence
- [`docs/next/WHAT-THE-OLD-APP-HAD.md`](../WHAT-THE-OLD-APP-HAD.md) — rows D1–D20, the E rows and the G rows, most of
  which are undecided
- [`0010`](../../decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md),
  [`0015`](../../decisions/0015-a-bundle-names-a-pattern-it-never-explains-one-away.md),
  [`0023`](../../decisions/0023-a-finding-has-a-stable-identity.md),
  [`0026`](../../decisions/0026-one-answer-to-whether-runs-may-be-compared.md) and
  [`0027`](../../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) — what
  is already settled about findings and comparison

**Then read the code.** At minimum: `DerivedAnalysisPipeline`, `ControlEdgeService`,
`EscalationPathService` and its data access, the tier classifiers under `EscalationPaths/`, the
evaluators under `Findings/`, `RuleEvaluatorHelpers`, and `StructuralCompareEngine`. The map names
more.

## The work

**For each component, ask four questions and write the answers down:**

1. **What shape is this?** Not what it does — what *kind* of thing it is. A materialised closure, a
   pipeline phase, a cache, an aggregate, an inventory.
2. **What is that shape assuming?** Every shape encodes a belief about how it will be used. A
   materialised all-pairs closure assumes every pair gets asked about. A per-object payload assumes
   objects are read one at a time.
3. **Is the assumption true?** Checkable — by reading what consumes the thing, by counting call
   sites, by measuring.
4. **What would a different shape cost**, including the cost of discovering the current one is fine?

**Hunt for one specific failure**, because it has now appeared twice in this codebase and was
invisible from either component alone:

> a decision justified by a claim about a **different** component, where nothing ever re-checked the
> claim — because the two components are reviewed separately

`F-S20-14` is the worked example. Inherited entries were dropped on the recorded grounds that
*"control edges, findings, and escalation paths only need explicit ACEs"*, and the graph that was
supposed to rely on that never modelled containment at all. **The claim was in a commit message for
years.** Read every load-bearing claim against the code that is supposed to depend on it.

**Specific questions this session should be able to answer when it finishes:**

- **Does the escalation search terminate correctly, and what bounds it?** Depth limits, budgets,
  cycle handling. `fact_expansion_status` carries `budget_exhausted` and `depth_reached`, so
  something gives up somewhere — and what a customer is told when it does is the interesting part.
- **What happens to a path when coverage is incomplete?** `coverage_complete` appears on control
  edges, paths and findings. Is it computed, propagated, or defaulted — and does anything render a
  path differently because of it?
- **How is Tier 0 decided, and what happens when it is wrong?** This is challenge 4 in the design
  document, and the classifiers under `EscalationPaths/` are where the answer lives.
- **Do the rules query storage directly?** The evaluators issue SQL — 15 queries against
  `fact_control_edge`, 18 against `dim_delegation`, 3 against `fact_ace`
  (`git grep -ho "FROM fact_[a-z_]*\|FROM dim_[a-z_]*" -- src/SecureAD.Infrastructure/Findings/`).
  Each is a place storage and rules are coupled. Is that a problem in practice, or theory?
- **What does compare actually compare**, and can it distinguish a changed forest from a changed
  rule, a changed tier definition, or a changed pipeline?
- **Is the deny model correct?** `RecordControlEdgeDiagnostics` writes
  `control_edge_deny_model = BestEffortSameObjectTrusteeObjectTypeMaskWithSidHistory`. The words
  *best effort* in a security control are worth a careful read.

**Rank what you find.** A challenge nobody can act on is noise. Rank by how much it changes what the
product can say, how much more expensive it gets later than now, and how confident the reading is.
**Mark each as evidence-backed or opinion.**

## Rules

- Product decisions are the owner's. Present them with options and costs, and wait. Engineering
  decisions are yours: decide, then say what it cost. **A brief saying "decide X" is not delegation
  of a product decision.**
- **This session decides nothing and builds nothing.** Its output is a document. A challenge arriving
  with code attached has skipped the step where the owner disagrees.
- **Where a judgement rests on what the old implementation did, read the old implementation.**
  [`docs/map/`](../../map/README.md) names the file; it is not the evidence. Three claims taken from
  it on 2026-08-12 were contradicted by the code, and two had already been built on.
- Nothing inherited is definitive, per [`0033`](../../decisions/0033-nothing-inherited-is-definitive.md).
  That includes the architecture, not only the components.
- **Do not type a count into a finding. Write the command that produces it**, next to the number. See
  the finding block in [`docs/review/TEMPLATE.md`](../../review/TEMPLATE.md).
- **State confidence honestly.** *Verified* means read; *suspected* means inferred;
  *needs-environment* means it needs a forest. A confident sentence resting on a schema rather than
  its code is the error this session is most likely to make, because a schema is so much faster to
  read — and it is the error `S-20` had to correct in itself twice.
- Records are corrected in place per
  [`0032`](../../decisions/0032-a-decision-record-is-corrected-in-place.md), Context sections
  excepted — but this session corrects none, because it decides none. A challenge to an accepted
  record is a finding that says a new record may be needed, and the owner decides.
- `src/SecureAD.*` and `tests/SecureAD.*` are frozen, and are read-only here in any case.
- Scratch files are written to `$env:TEMP`, never inside the repository. Do not stage with
  `git add -A`; name the files.
- No multi-line here-strings in PowerShell. Write long text to a file and read it.

## Finish by

- Writing `docs/next/S-22-[slug].md` in the [`docs/review/TEMPLATE.md`](../../review/TEMPLATE.md)
  shape, with a status on every finding and a **verified-safe** section that is not empty — a review
  of a working product that found nothing worth keeping was not a review
- **Answering the six specific questions above**, or saying plainly which could not be answered and
  why
- **Ranking the challenges**, with the criteria stated, and marking each evidence-backed or opinion
- Recording, for each challenge, **what would settle it** — a measurement, a reading, or an owner
  decision
- Confirming, refuting or extending challenges 1, 3, 4 and 5 in
  [`DESIGN-challenges-to-the-inherited-shape.md`](../../history/DESIGN-challenges-to-the-inherited-shape.md),
  and updating that document's status where the reading has moved it
- Naming any challenge that contradicts an accepted decision, with the record named and **no edit
  made**
- Naming the slice document in [`docs/next/README.md`](../README.md) §`Status`, which
  `RebuildStatusDocumentationTests` requires
- Adding the new documents to `next/SecureAD.Next.sln` so they appear in Solution Explorer
- Appending one entry to [`docs/review/SESSION-LOG.md`](../../review/SESSION-LOG.md), in plain
  language
- Running `dotnet build next/SecureAD.Next.sln` and the full test suite
- **Reading** `git status --porcelain` over the whole repository — reading the list, not counting it
  — and `git diff --numstat` before committing
- Committing, with the message written to a file outside the repository rather than a here-string
