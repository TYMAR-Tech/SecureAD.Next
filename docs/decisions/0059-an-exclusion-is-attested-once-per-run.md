# 0059 - An exclusion is attested once per run and never carried forward

Date: 2026-08-16
Status: Accepted

Amends [0052](0052-the-domain-is-the-only-unit-of-scope.md), which decided an operator may exclude a
domain under attestation but not how long that attestation lasts. Answers `A3` of the
S-44 agenda.

## Context

[`0052`](0052-the-domain-is-the-only-unit-of-scope.md) carries forward
`0049`'s rule that a domain may be left
out of a run only if the operator states a posture for it. Neither record says whether that
statement is made once and remembered, or made again every time.

The predecessor's own reasoning is quoted in `0049` and it is the argument that settles this:

> an attestation the user clicks through is a liability waiver, not a safety mechanism. It becomes
> one by being tested.

An attestation remembered from a previous run is not clicked through - it is not seen at all, which
is worse.

## Decision

**An exclusion belongs to one run. The next run starts with nothing excluded.**

**An operator who wants a domain excluded again must say so again, and state the reason again.** The
reason is not pre-filled from last time, and the product does not suggest it.

The situation being guarded against is the one that actually happens: a domain is excluded in
January because the credentials had not arrived, the credentials arrive in March, and the audit goes
on reporting a clean forest with a hole in it that nobody has looked at since. The excluded domain
does not announce itself. The only thing that reliably surfaces it is the operator being asked,
every time, and having to type a reason that is no longer true.

**Pre-filling was considered and refused.** A remembered reason presented for confirmation is a
button an operator presses without reading by the third run, and it produces exactly the stale
attestation above while looking like it does not. The friction here is the control. Making the
common case comfortable is what breaks it.

**Scope of the rule.** This governs the exclusion an operator *chooses*. A domain with no reachable
candidates is a different event, recorded under
[`0054`](0054-a-domain-with-no-candidates-is-an-attested-exclusion.md), and nothing here changes it.

## Consequences

**Repeat audits of a forest with a permanently out-of-remit domain cost the operator a typed reason
every run.** Accepted, and it is the point rather than a side effect. If that proves genuinely
unworkable at, say, monthly cadence against a large forest, the answer is a new record making the
case - not a quiet default.

**Scheduling collides with this.** A run that nobody is signed in for cannot attest to anything, so
either a scheduled run refuses to exclude any domain, or scheduling needs its own answer. Scheduling
is undecided (`C1` of the agenda) and this record does not decide it; it records that the two
questions meet.

**Each run's bundle carries its own attestation**, because each run has its own. What that
attestation asks for, and whether its text reaches the bundle, is still open - `A5` of the agenda.

**The New Audit wizard cannot show a domain as pre-excluded.** Every run's domain list starts with
every domain in.
