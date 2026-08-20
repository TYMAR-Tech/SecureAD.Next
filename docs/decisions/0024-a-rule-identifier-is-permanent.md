# 0024 - A rule identifier is permanent and is never reused

Date: 2026-08-12
Status: Accepted

## Context

Per [`0023`](0023-a-finding-has-a-stable-identity.md) a rule's identifier is part of every finding's
identity, so renumbering a rule orphans every acceptance made against it. A customer who accepted a
finding six months ago would find it back, with no explanation, because a number changed.

Rule identifiers also travel outside this product. They appear in reports, in remediation tickets,
and in conversations between an administrator and an auditor. A number that means one thing this
quarter and something else next is worse than a number nobody uses.

## Decision

**A rule identifier is permanent and is never reused.** Once issued it belongs to that rule for good,
including after the rule is retired.

Retiring a rule does not free its number. A retired rule stays in the catalogue, marked retired, and
**declares what supersedes it** where something does.

Because the catalogue is data rather than code
([`0010`](0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md)), this is enforced rather than
trusted: an identifier that disappears from the catalogue without being marked retired fails the
build.

## Consequences

What genuinely happens to rules is not renumbering. It is lifecycle - a rule is split into two,
two are merged, or one is replaced by a better one. Those are expressible as retirement plus a
supersedes link, and they are visible to a customer instead of appearing as a number that moved.

Per `0023` a supersedes link is reported and never silently carries an acceptance across it.

The cost is that the catalogue accumulates retired entries and its numbering develops gaps. That is
the correct trade: a gap in a numbering scheme is a curiosity, and a reused identifier is a customer
being told a finding they accepted has returned, or worse, a finding being suppressed by consent
given for something else.
