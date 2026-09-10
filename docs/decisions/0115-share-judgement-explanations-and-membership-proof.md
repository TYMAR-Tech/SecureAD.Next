# 0115 - Share Judgement explanations and membership proof

Date: 2026-09-09
Status: Accepted.

The owner explicitly approved S1 and its two-pass lab validation after reviewing the
[bounded storage redesign](../layers/judgement/the-judgement-store.md#proposed-bounded-proof-storage-redesign-and-validation-plan).
This accepts the first slice, not every follow-on or production-scale acceptance.

## Decision

Within one immutable Judgement generation, store exact repeated trustee explanation text and
complete ordered membership-route values once, with checked consumer references. Reconstruct the
existing public permission and full-control models before validation or presentation. Preserve
source generations, scoped identities, ordinals, masks, flags, GUID strings, callback bytes,
independent routes, full-control supports, expectedness and explicit incomplete results. Neither
hash equality alone nor matching row counts establishes proof equivalence.

Only Judgement storage/schema adapters, their tests and governing documentation may change in S1.
The shared MembershipRouteStorage implementation used by Derivation remains unchanged; finding-owned
route storage remains independent. Preserve object transactions, rollback and atomic publication.
Do not combine transaction batching, evaluator changes, reader-validation lifetime changes,
identity-key compaction, graph-memory redesign or UI changes with this slice.

Use Judgement schema 27 for the changed persisted representation; control engine 9 and principal
catalogue 3 retain their existing semantics. Evidence and Derivation formats do not change. Do not
migrate, relabel or overwrite historical generations or modify frozen checkpoints/comparers.

## Measurement authorization

A separate comparison artifact may perform exactly two additional lab judging executions:
one before S1 and one after, using the same sealed ad.lab-20260909-050807 inputs and fixed evaluation
time 2026-09-09T05:08:22.3459193+00:00. No warmups, averaging or automatic retries of a consumed
execution slot. Each pass includes completion readback and the same bounded first/repeated reads.
Keep a previous sealed judgement alongside the new generation to observe retained-generation disk
cost. Preserve binaries, actual runtime/build identities, logs, outputs and all original evidence.

The pinned selections from the retained lab output are:

- Assessed object: CN=Account Operators,CN=Builtin,DC=ad,DC=lab.
- Unassessed object: CN=00232167-f3a4-43c6-b503-9acb7a81b01c,CN=Operations,CN=ForestUpdates,CN=Configuration,DC=ad,DC=lab.
- Named holder: S-1-1-0, null resource scope; four control edges in this capture.

Each page request opens its own reader, matching the current Shell caller's lifetime. Selections
and comparison logic are frozen after the successful before pass. The old lab benchmark and
ScopedOwnershipSingleReplayBenchmarks, their counts, and the consumed one-shot claim stay unchanged.
Compare complete changed values and every consumer binding with independent ordered digests and
bounded public-model reads; do not run the old expensive exhaustive public exports.

## Validation and remaining boundaries

Require exact-value, cross-domain, corruption/redirection, rollback and cancellation tests; unchanged
basic findings, primitive/support counts, scope and inactive requester/member products; and a measured
net database reduction including indexes/references. Report runtime/readback/memory regressions rather
than hiding them with another optimization. A failing parity or material unexplained regression gate
stops the slice; another measured run requires approval.

The four StageStatusGateTests remain excluded. No production budget/activation, live access,
recapture, service/power changes, commit/push/reset, deletion of prior evidence or production-scale
workload is authorized. Lab results do not establish customer acceptance.
