# 0116 - Discovery-first assessment admission

Date: 2026-09-10
Status: Accepted.

The owner explicitly approved discovery-first assessment admission on 2026-09-10, after reviewing
the broad-principal treatment, the schema-28 rationale, the proposed scope wording and the retained-route
addition. This accepts the work-boundary change and its read/count consequences, not a path
presentation feature, a production budget or production-scale acceptance.

## Why

`JudgingRun` derives detailed control and full-control products for every streamed object and
`OwnershipAuditRun` then reads those stored edges to select what mattered. The lab measured
112,093 control records and 23,751 full-control assessments across 8,407 objects to justify
51 assessed ownership targets and 210 ownership records, with `EvaluatingObjects` taking
35.7 seconds of a 50.6-second run. The expensive work is paid before anything decides it is needed.

Storage tuning alone was measured and rejected as the answer: 0115 reduced the database 10.51%
while elapsed time rose 9.22% and cumulative allocation rose 20.47%. That performance hold stands.
This decision changes which work runs, not how its output is stored.

## Decision

Within judging, discovery runs before detailed assessment and determines its scope.

Ordinary rule evaluation is unchanged and independent. Every scheduled rule is still offered every
streamed object exactly once, reading captured facts from Evidence. No rule consumes the control
store, and existing findings, severities and coverage are preserved unchanged.

Discovery observes captured owners, permissions and source-bound membership during the existing
single object stream, in the manner of the existing `SelfMembershipScheduler`: a bounded scan that
collects candidates and typed limitation reasons without invoking the detailed evaluators. It must
not require completed control products, and must not materialize an expanded forest-wide permission
model to decide scope.

Discovery starts at the supported Tier-0 seeds of the one authoritative shared classifier and follows
**incoming** controller and membership relationships. A Tier-0 principal's outgoing control of an
ordinary object does not admit that object. Relevance does not relabel an object as Tier 0.

Detailed control, full-control and hypothetical ownership-transition evaluation run only for admitted
targets. Each target is assessed once per generation; later inclusion reasons are retained without
re-evaluation. Admitted targets reuse the existing evaluators; their permission semantics, expectedness,
proof and independent-route handling are unchanged.

Captured facts remain readable for every object. Owner and raw permissions are shown independently of
whether detailed assessment ran. An object that discovery did not reach is recorded as not assessed
automatically, which is never a statement that it is safe, empty or unimportant.

## Retained discovery routes

Discovery records the controller/target relationship and its reason for each admitted object, bound to
the source evidence, rather than discarding the route after admission. Today `ownership_relation`
stores `edge_id`, `controller_target` and `affected_target` with a foreign key into `control_edge`;
that dependency does not survive discovery running first, so the retained route references its
capture-backed witness instead.

Two existing store dependencies change with it. `ownership_target.target` references
`control_object(target)`, and `OwnershipAuditStorage.Observe` is currently reached only from
`ControlEdgeStorage.Write`, so today an ownership target can exist only where the detailed pass
already wrote a control object. Ownership targets are instead recorded from the streamed object during
discovery. `Tier0RelevanceRelation.FromControlEdge` requires a persisted edge and remains valid for
relations sourced from stored edges; capture-backed candidates use a separate constructor rather than
being given a synthesized edge identity.

This retains the answer the existing walk already computes. It is not a path presentation, ranking,
remediation or all-path enumeration feature, and none of those become prerequisites here. Chained
paths to Tier 0 remain later-stage work that reads these stored routes rather than re-traversing.

## Broad principals

A broad principal such as Everyone, Authenticated Users or Domain Users, and a NULL DACL, is recorded
as one explicit unresolved candidate with its source witness and honest incomplete coverage. It is not
expanded into individual accounts, not silently truncated, and not omitted.

Expanding such a route would make effectively the whole forest relevant and reintroduce the cost this
decision removes, while repeating one fact per account. Omitting it would imply a safety this product
never established. The remediation is the single permission entry, which the route names directly.

Existing rules that report broad-principal exposure, including SEC-060 `BroadPrincipalCanTakeOverObject`,
read permissions directly from Evidence and continue to report independently of discovery scope.

## Schema and versions

Use Judgement schema 28. Evidence and Derivation formats do not change.

Schema 28 is required because stored meaning changes while stored shape does not. `ControlEdgePage`
counts (`UnexpectedCount`, `UnknownCount`, `ExpectedCount`, `UnansweredObjects`) currently mean
"across the captured forest" and afterwards mean "across the assessed scope". A schema 27 file and a
schema 28 file would otherwise be indistinguishable while meaning different things, and a reader
would silently present scoped counts as forest-wide totals. Older generations are re-judged for
current readback; they are not migrated, relabelled or overwritten.

Control engine 9 and principal catalogue 3 retain their existing semantics. Frozen comparers,
golden values and historical measurement artifacts are unchanged.

## Presentation

Existing approved status wording is retained: **Assessed automatically from captured evidence**,
**Not assessed automatically**, and **Not assessed automatically: required derived inputs are
unavailable**.

Control-edge counts require added scope wording, because they otherwise read as forest-wide totals.
The wording below is approved in substance as part of this decision; its exact final rendering and
placement on the screen are confirmed with the owner before the Shell edit is made:

> Counts cover objects assessed automatically from Tier-0 discovery, not the whole forest. Objects not
> reached were not assessed automatically; this is not a statement that they are safe.

No on-demand action button, no new top-level screen and no layout change is approved here. Passive
pages remain read-only and must not perform discovery or write analysis while opening.

## Acceptance

An unrelated ordinary account receives its captured facts and ordinary rule findings, with zero
automatic detailed control, full-control or owner-transition calls and no detailed control proof
written. The same account reached through a supported incoming Tier-0 route is admitted with a
source-linked reason and assessed, without being relabelled Tier 0.

Required call-count tests carry a negative control proving they detect deliberate evaluation of an
unrelated object. Missing seed qualification, membership or permission evidence produces typed
incomplete coverage, never a safe, unimportant or empty-success result and never a silent forest-wide
fallback. Cancellation or failure before publication leaves the previous published generation selected.

The old all-object control and full-control counts are history, not acceptance oracles; reducing those
products is the intended change. Scope-aware acceptance tests are added under new identifiers rather
than by editing frozen expectations. The 13 known offline failures are investigated against the
retained pre-S1 baseline and not weakened to obtain a green total. The four StageStatusGateTests
remain excluded.

## Boundaries

No new timed judging run, measurement harness or benchmark is authorized by this decision; the
one-shot and both S1 claims remain consumed. Production-scale acceptance against the recorded
nine-domain shape of approximately 347,000 objects and 5.9 million access control entries remains
separate and outstanding, as does Stage 6 acceptance.

No live forest access, recapture, production discovery or member-expansion budget, host activation,
service or power change, commit, push, reset or deletion of prior generations is authorized. Lab
results do not establish customer acceptance.
