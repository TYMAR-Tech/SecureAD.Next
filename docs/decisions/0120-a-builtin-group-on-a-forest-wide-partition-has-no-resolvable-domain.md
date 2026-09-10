# 0120 - A BUILTIN group on a forest-wide partition has no resolvable domain

Date: 2026-09-11
Status: Accepted.

The owner approved the operator wording and its scope on 2026-09-11. This changes what an operator is
told about four rows in the laboratory run. It changes no assessment, no count and no stored proof.

## Why

`P-90` asked which domain is the authorization context for an object outside a domain naming context.
It has sat open since 2026-08-26 as though it were a gap in the capture. It is not. It is a property
of Active Directory, and three first-party pages settle it between them.

**A domain local group reaches one domain.** Microsoft's group-scope table gives a domain local
group's membership reach across the forest and its *scope* as
[within the same domain](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups).

**Which domain is decided at the resource, not at the group.** The access-check description says the
token built for the request carries the SIDs of the domain local groups
[in the target domain](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups).
So the entry names a group whose identity depends on where the check happens.

**And every domain's copy carries the same SID.** BUILTIN\Administrators is domain-local, exists once
per domain, and is `S-1-5-32-544` in all of them -
[Appendix B](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory).
The SID does not distinguish them, because it was never meant to.

**A forest-wide partition owns no domain.** The configuration and schema naming contexts replicate to
every controller in every domain. There is no target domain for the rule to turn on. The question is
therefore not unanswered - it is unanswerable, and capturing again with different settings cannot
change that.

## Decision

`ControlUncertainty.ResourceContextUnverified` on a BUILTIN holder outside a domain naming context is
a **documented limit**, not a defect. It stays. The product stops presenting it as a bare `Unknown`
and states the reason, including that a re-capture will not settle it.

Two things are said, both in `ControlEdgePresentation.resx`:

- `DomainLocalScopeOnForestPartition` explains the rule in the evidence panel.
- `HolderScopeNotVerified` marks the recorded scope as *recorded, not resolved*.

The second exists because capture stamps the forest root on objects that belong to no domain, since
something must be written. Printing `contoso.com` plainly beside `S-1-5-32-544` would tell an operator
the product had worked out which domain's Administrators the entry means. The value is kept, because
hiding evidence is worse; it is marked, because showing it bare states something untrue.

## Scope, and why it is not the uncertainty flag

The explanation is shown when the holder is BUILTIN **and** the flag is set - not on the flag alone.

Fourteen edges of 1,172 in `ad.lab-20260910-074140` carry `ResourceContextUnverified`. Four are this
case: `S-1-5-32-544` on the Configuration and Schema roots. The other ten are
`UnknownCapabilityScope`, a different open question. Selecting on the flag would answer ten rows with
a reason that does not describe them - a confident wrong answer, which is worse than an unexplained
one, and squarely the failure `docs/next/README.md` puts first.

`AnotherReasonDoesNotBorrowThisExplanation` is the negative control. It was verified by broadening the
predicate to the flag alone and confirming the domain-principal case fails.

## What this cost, and what it did not

**No judgement changes.** The flag is still set by the same rule at the same two sites in
`ControlEdgeDeriver`; the evaluation state, the counts and the stored proof are untouched. No schema
moves.

**`P-90` closes as a documented limit, not a fix.** Nothing was repaired. What changed is that the
product now says why, and the deriver comment cites the rule instead of recording a doubt.

## Consequences

- The instruction recorded with `P-90` - that `resourceDomain` must not harden into an API contract
  before this is answered - is now settled rather than pending. It is answered: for a forest-wide
  partition there is no resource domain to contract on.
- The application-partition case `P-90` also raised is **not** closed here. `DomainDnsZones` and
  `ForestDnsZones` list writable replicas in `msDS-NC-Replica-Locations`, and a local group in such an
  ACL is a different problem with a different answer. This decision covers configuration and schema.
- An operator who reads `Unknown` with no explanation reaches for a re-capture. That is the afternoon
  the primary-group wording wasted before [`0118`](0118-primary-group-only-membership-is-not-protected.md);
  the closing sentence exists to prevent the same reach here.
