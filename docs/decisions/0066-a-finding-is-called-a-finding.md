# 0066 - A finding is called a finding, and its severity is fixed by its rule

Date: 2026-08-16
Status: Accepted

Sits under [0010](0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md),
[0023](0023-a-finding-has-a-stable-identity.md) and
[0024](0024-a-rule-identifier-is-permanent.md). Answers `B2`'s vocabulary question and `B5` of the
[S-44 agenda](../next/sessions/S-44-agenda.md).

## Context

The product had no settled word for the thing it produces. `0023` and `0024` decide that such a
thing has a stable identity and a permanent rule identifier without naming it, and the predecessor
used two vocabularies at once - *finding* on screen, *suppression* in the code - for one idea.

A word chosen late is a word already written into thirty screens, every report, sixty-two rule cards
and a database schema. This is the cheapest hour it will ever cost.

## Decision

**The thing the product finds is a finding.** Not an issue, not a risk, not a result. One word, on
every screen, in every report, in every rule card, in every table name and every type name.

**A finding an operator has judged acceptable is accepted.** Not suppressed, not excepted, not
waived. The predecessor's split - *Accept Finding* in the interface and `Suppression` throughout the
code - is not carried across. The two words describe the same act to two audiences, and a reader who
learns one still cannot search for the other.

**Severity is fixed by the rule card and the customer cannot change it.**

The predecessor could override severity through a policy file, with counters tracking how many
overrides were applied. The owner never used it. It is also the most direct way for a customer to
make a real problem invisible while the tool continues to report a clean forest - lowering a
severity is quieter than accepting a finding, because accepting one leaves an accepted finding
behind and a lowered severity leaves nothing at all.

**Accepting a finding is the supported way to say "this one is fine here".** It is per finding, it
carries a reason and a name, and it remains visible as an accepted finding. That is the route, and
one route is enough.

## Consequences

**A rule card's severity is part of the catalogue**, which is data under
[`0010`](0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md). Changing one changes it for
everybody, deliberately, in a place that is reviewed.

**This is not a refusal of customer policy for ever.** The owner's position is *fixed initially*,
and the question of whether a customer may tune the catalogue at all is genuinely open - it was
raised and never explored, because the predecessor's implementation went unused. Reopening it
requires a new record and the argument above to be answered, not merely a default flipped.

**The word `suppression` is retired.** Where it appears in ported prose or a ledger row describing
the predecessor it stays, because that is a description of the old system. Nothing new carries it.

**A test should hold the vocabulary**, on the same footing as the other documentation gates:
`finding` and `accepted` in the public surface, and neither `suppress` nor `issue` naming the same
idea. A word is only settled if drifting from it fails the build.
