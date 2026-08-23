# 0062 - What an exclusion attestation asks for, and that it reaches the bundle

Date: 2026-08-16
Status: Accepted

Amends [0052](0052-the-domain-is-the-only-unit-of-scope.md), which decided an operator must state a
posture to exclude a domain but not what he is asked or what becomes of the answer. Sits with
[0059](0059-an-exclusion-is-attested-once-per-run.md). Answers `A5` of the
S-44 agenda.

## Context

The attestation has been decided twice - in
`0049` and again in
[`0052`](0052-the-domain-is-the-only-unit-of-scope.md) - and has had no code, no test and no screen
in either. What it asks for was never written down, so nothing could be built without guessing.

## Decision

**The operator picks a reason from a fixed list, and may add free text.**

**The fixed list is what makes an exclusion answerable later.** Free text alone cannot be counted,
compared across runs, or tested against the captured data; twenty runs of prose is twenty things a
reader has to interpret. A closed list means the product can ask *"how many domains were excluded
for lack of credentials this year"* and get an answer.

**The free text is what stops the list lying.** A fixed list with no escape forces the operator to
pick the nearest wrong answer, and the nearest wrong answer is recorded as though it were right.

**The reasons are a closed set with permanent meanings**, on the same footing as a rule identifier
under [`0024`](0024-a-rule-identifier-is-permanent.md). A reason's wording may be improved; what it
means may not change, because runs already recorded carry it. The initial set covers the three
situations `0049` named - credentials not held, outside this audit's remit, and the domain believed
to hold nothing - and grows by record.

**Two parties are named: the account that ran it, and the person who authorised it.** The signed-in
Windows account is captured automatically and is not typed, because a name an operator types for
himself is a name he can get wrong. The authorising party is typed, because the operator frequently
is not the person whose decision it was, and an exclusion with no accountable name behind it is the
liability waiver `0049` warned against.

**The whole attestation reaches the bundle**: the reason, the free text, both names, and the time it
was made. An exclusion that governs a run but is not stored with it is a fact about the audit that
the audit does not carry, and the first person to need it is an auditor reading the run months
later, with the operator unavailable and the screen long gone.

## Consequences

**This is schema, and it is cheapest now.** Under
[`0013`](0013-the-bundle-is-no-longer-a-two-way-contract.md) and
[`0001`](0001-no-backward-compatibility.md) there are no bundles in the field to migrate, so the
table costs nothing today and cannot be added retroactively to evidence already taken.

**Every table says what its absence means**, per the rule `what-a-bundle-holds.md` binds. For this one: no rows means
no domain was excluded - it does not mean the attestation was not recorded.

**A report handed to an auditor can carry the exclusions**, and whether it must is `B4` of the
agenda, still open. This record makes it possible; it does not decide it.

**The falsifiable posture stays deferred.** `0049` offered to test a claim against the captured data
and demote the run when it proved false - *"the domain is empty"* can be checked, *"I lack
credentials"* cannot. That is still owed to ledger row `B11` and nothing here brings it forward. The
reason list should be drawn knowing which of its entries are one day checkable.

**The authorising name is not validated and cannot be.** It is a typed string, and the product must
not present it as though it were verified. It is a statement of accountability, not an identity.
