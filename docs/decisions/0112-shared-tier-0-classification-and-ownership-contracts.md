# 0112 - Shared Tier-0 classification and ownership contracts

Date: 2026-09-08
Status: Accepted.

The owner approved the application-wide direction, then explicitly approved the bounded
implementation slice in Stage 6 section 15, including reconciliation of 0006 and 0099.

## Decision

Target importance uses one shared, evidence-backed Tier-0 model. Ownership assessment consumes
that model; it does not maintain a separate important-object list or derive importance from
expected administration, owner acceptance, AdminSDHolder protection or rule severity.

[0006](0006-tier-0-and-expected-admin-are-separate-sets.md) remains the core identifier policy.
Its membership is not duplicated here. The sentence in 0099 excluding the Domain Controllers
group from Tier-0 objects is corrected: the group remains a core target under 0006, but is not
itself a domain-controller computer or an expected control-plane principal. This correction also
requires filling the shared classifier's omitted 0006 members, with proper identifier and
resource context. No expectedness or accepted-owner predicate changes with it.

Shared results distinguish core classification, effective security-group membership, qualifying
established direct control, and longer or conditional relevance. Each positive classification
needs its own evidence and scope. A possible relation can justify assessment without establishing
Tier-0 classification or a completed takeover. Existing protection-rooted membership summaries
are reusable positive witnesses, not the complete Tier-0 population; absence is not a negative.
An established primitive permission does not establish an unverified operation or ownership
transition. Independent supports and missing/unsupported inputs remain explicit.

The approved first implementation adds the central correction, source-bound shared contracts,
supported core and existing-membership adapters, directed relevance contracts, ownership
scope/result contracts, and offline tests. The shared principal catalogue changes version;
unchanged catalogue-2 full-control semantics remain replay-readable. This is not an audit
selection change and does not introduce new persisted tables, an object runner, or a UI.

## Ownership contract

The approved eventual automatic scope remains core Tier 0 and identified controllers/dependencies.
Other objects receive detailed assessment only by an explicit offline single-object request.
The audit and request will share one evaluator. Preserve current-owner findings, primitive
permissions, full-control supports, alternative grants and group-held counts.

Automatic results belong to a new immutable Judgement generation. Explicit results will use
small, separately sealed target generations bound to the Evidence seal, Derivation and relevant
Judgement generations, target/resource identity, evaluation context and semantic versions.
Not assessed, assessed with unknowns, cancelled, failed, unavailable and stale are distinct.
Ordinary readers never trigger evaluation. Publication must preserve the previous selected result
on failure or cancellation before its atomic commit point. These publication mechanics are a
contract for a later slice, not an implemented store in this slice.

## Boundaries

No complete selector, recursive path engine, new membership/requester expansion, production budget,
UI wording/layout, live directory access, recapture, measurement harness, frozen benchmark change,
commit or push is approved. The ownership assignment/server-behavior gate remains open. New public
contracts are tested and documented; no runtime, storage-saving or production-acceptance claim
follows from this foundation.

The [Stage 6 contract](../next/SPEC-stage-6-control-edges.md#15-proposed-shared-tier-0-and-ownership-contracts)
records the detailed boundaries and subsequent implementation status.
