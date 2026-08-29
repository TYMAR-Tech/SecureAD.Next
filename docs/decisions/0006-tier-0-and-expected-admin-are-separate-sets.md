# 0006 - Tier-0 membership and expected-admin suppression are separate sets

Date: 2026-08-07
Status: Accepted. The separation of the two sets stands. The Tier-0 membership below was corrected
on 2026-08-22 by the owner: the four operator groups (548, 549, 550, 551) and Cert Publishers (517)
are Tier 0, against Microsoft's [Tier model for Active Directory Domain
Services](https://learn.microsoft.com/windows-server/identity/ad-ds/tier-model), which defines Tier
0 by control over the directory and names Backup Operators and Server Operators among its built-in
groups. Expected-admin keeps its membership and is now written out rather than derived from Tier 0.
The Context below is left as written because that reasoning is how the error entered.

**Correction 2026-08-28 under [`0089`](0089-principal-protection-and-member-propagation-are-separate-claims.md):**
the separation still stands, but this record's sentence that Microsoft protects Enterprise Read-only
Domain Controllers (RID 498) unconditionally is superseded. Current first-party sources conflict:
the group-specific Microsoft page says `Protected by AdminSDHolder? Yes`, while Appendix C omits the
group. RID 498 remains in these product policy sets as the owner's Tier/expected-admin classification;
that policy membership is not evidence that AdminSDHolder protection is established. The shared
AdminSDHolder catalogue carries principal protection as `Disputed` and member propagation as
`Unverified`.

## Context

Two different questions are answered from one list of well-known RIDs: *is this principal
something an attacker wants to reach*, and *is this principal's privilege unremarkable enough
that a finding about it may be suppressed*. They are not the same question, and the product
already answers them differently without being able to say so — the operator groups (Account,
Server, Print, Backup) are deliberately excluded from high-value targets, because escalation paths
*from* them are worth reporting, while a presentation helper treats those same groups as admins to
filter out. One list cannot express that; it can only be right about one of the two.
**— The exclusion is wrong and the four operator groups are Tier 0, per Microsoft's *Tier model for
Active Directory Domain Services*, which names Backup Operators and Server Operators among its Tier
0 built-in groups. Cert Publishers (517) was added at the same time. Paths *from* a group were never
a reason to refuse paths *to* it. The observation that one list cannot answer two questions is
sound, and is what this record is for; the membership drawn from it was not. This paragraph is kept
because it is how the error entered — the exclusion was inherited from the predecessor, where
`HighValueTargets.cs` carries the same reasoning in a comment, and it passed review unread.**

The answers also diverge for Group Policy Creator Owners. Microsoft does not protect it with
AdminSDHolder and does not list it among protected accounts and groups, yet documents it as
authorised to create, edit and delete Group Policy Objects and as unsafe to delegate to
non-service administrators. It is worth reaching, and its privilege is not unremarkable.

## Decision

There are two named sets, each recording the question it answers.

**Tier-0 RIDs** — what an attacker wants to reach, so paths to it are elevated:
498, 500, 502, 512, 516, 517, 518, 519, 520, 521, 526, 527, 544, 548, 549, 550, 551.

**Expected-admin RIDs** — whose privilege is by design, so a finding about it may be suppressed:
498, 500, 502, 512, 516, 518, 519, 521, 526, 527, 544.

**Each set is stated in full, and neither is derived from the other.** Expected-admin was once
*the same set without 520*, and that arithmetic tied together the two answers this record exists to
keep apart: a principal added to Tier 0 was silently granted suppression as well.

Enterprise Read-only Domain Controllers (498) and `BUILTIN\Administrators` (544) belong to both.
Microsoft protects both with AdminSDHolder and describes the built-in Administrators group as
effectively equivalent to Domain Admins and Enterprise Admins.

**The operator groups are Tier 0, and none of them is an expected admin.** Account (548), Server
(549), Print (550) and Backup (551) Operators, and Cert Publishers (517), are Tier 0 because
Microsoft defines Tier 0 as the assets and identities that *directly or indirectly control the
directory service*, names Backup Operators and Server Operators among its Tier 0 built-in groups,
and lists AD CS — which Cert Publishers controls — as a Tier 0 identity service. Server and Backup
Operators can back up and restore a domain controller, and a domain controller's backup is the
directory. Microsoft's rule that the sensitivity of all Tier 0 assets is equivalent, because they
are all effectively in control of each other, admits no gradation here.

None of the five is an expected admin. Microsoft's guidance is to apply least privilege *within*
Tier 0, and it names backup and monitoring agents holding administrative rights as an anti-pattern
rather than a design. An ACE granting one of these groups control over an arbitrary object is
therefore not privilege by design, and is reported. Where an organisation still uses these groups
and does not want the volume, that is a question for presentation, not for this set: suppression
here would also silence the paths that reaching Tier 0 is supposed to raise.

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

The Tier-0 set gains five members, and paths ending at them are now elevated. The four operator
groups were previously excluded on the grounds that escalation paths *from* them are worth
reporting. That is true, and it is not a reason to exclude them: a group can be both somewhere an
attacker arrives and somewhere an attacker departs, and treating the two as alternatives is what
produced the error.

Expected-admin does not change its membership. It changes only in being written out rather than
computed, so the next principal added to Tier 0 does not quietly acquire suppression with it.

No production code holds either set, so nothing in the build changes. When the graph engine is
written it takes these lists as given.
