# 0006 - Tier-0 membership and expected-admin suppression are separate sets

Date: 2026-08-07
Status: Accepted

## Context

Two different questions are answered from one list of well-known RIDs: *is this principal
something an attacker wants to reach*, and *is this principal's privilege unremarkable enough
that a finding about it may be suppressed*. They are not the same question, and the product
already answers them differently without being able to say so — the operator groups (Account,
Server, Print, Backup) are deliberately excluded from high-value targets, because escalation paths
*from* them are worth reporting, while a presentation helper treats those same groups as admins to
filter out. One list cannot express that; it can only be right about one of the two.

The answers also diverge for Group Policy Creator Owners. Microsoft does not protect it with
AdminSDHolder and does not list it among protected accounts and groups, yet documents it as
authorised to create, edit and delete Group Policy Objects and as unsafe to delegate to
non-service administrators. It is worth reaching, and its privilege is not unremarkable.

## Decision

There are two named sets, each recording the question it answers.

**Tier-0 RIDs** — what an attacker wants to reach, so paths to it are elevated:
498, 500, 502, 512, 516, 518, 519, 520, 521, 526, 527, 544.

**Expected-admin RIDs** — whose privilege is by design, so a finding about it may be suppressed:
the same set **without 520**.

Enterprise Read-only Domain Controllers (498) and `BUILTIN\Administrators` (544) belong to both.
Microsoft protects both with AdminSDHolder and describes the built-in Administrators group as
effectively equivalent to Domain Admins and Enterprise Admins.

Where evidence bears on the question, it escalates severity; it never suppresses. Absence of a
control edge is not proof the right is absent — capture can be partial, which is why coverage
completeness travels with edges and paths.

## Consequences

Suppression becomes a deliberate act that names the set it draws on, rather than a side effect of
sharing one list with the targeting logic.

Adding 544 removes noise: `BUILTIN\Administrators` appears as an ACE trustee throughout a forest,
and findings about it were previously raised.

Removing 520 adds findings only where they are wanted. The group's sole default member is the
built-in Administrator account, which is covered by RID 500, so a default forest gains nothing.
Findings appear where members have actually been added — the case worth seeing.

The Tier-0 set's membership does not change. It is what the product already declared, in two
identical copies; the decision is that there is one home for it and a second, different set beside
it.
