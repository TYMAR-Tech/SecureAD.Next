# 0064 - An attribute is justified by a rule or by the object view

Date: 2026-08-16
Status: Accepted

Widens the justification rule that
`S-23` binds by test. Sits under
[0010](0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md). Answers the gate question raised
under `B1` of the S-44 agenda.

## Context

The catalogue of captured attributes is held to a rule enforced by
CapturedAttributeDerivationDocumentationTests: **every attribute must name something that reads
it**, and today that something must be a rule card. It exists to stop the catalogue becoming a junk
drawer, and it works.

It also has a cost that only became visible when the catalogue was examined against the
predecessor's. An attribute not captured is a question **no past run can ever answer**. There is no
backfill: the catalogue version is stamped into every bundle, and the record of the last increment
says it plainly - *"a bundle stamped 1 therefore cannot support a LAPS finding however it is
analysed later."*

The two costs are wildly asymmetric. Adding an attribute costs one line, because capture asks every
object for the whole catalogue regardless of class and the query does not change shape. Not adding
it costs every run taken until somebody notices.

The strict rule therefore guarantees that **every new rule begins with a year of blind runs** - the
attribute is added when the rule is written, and no run before that date can answer it.

## Decision

**An attribute belongs in the catalogue if it is read by a rule, or if it fills a field of the
object view.** Either justification is written down and either is sufficient.

**The object view is a first-class consumer, not a decoration.** It is the screen an operator opens
to understand one object - its owner, its state, when its password was last set, whether its local
administrator password is managed. The predecessor had one and it was used. Attributes that exist
only to answer *"what is this thing?"* are doing real work, and the strict rule had no way to say so.

**The junk-drawer guard is kept whole.** Nothing enters unexplained. An attribute with neither a
rule nor a view field behind it is still refused, and the justification is still checked by test
rather than by intention.

**Speculative capture remains refused.** *"We might need it"* is not a justification, and neither is
*"a rule we may write later"*. The line is between an attribute serving something that exists and an
attribute serving something imagined - not between rules and everything else.

**A consequence, stated so it is not discovered later**: this deliberately declines to capture
evidence for capabilities not being built. Certificate services is the worked example - a large body
of evidence for rules the product has not decided to write. It stays out until that decision is
made, and the run that follows the decision is the first that can answer it. That cost is accepted
knowingly here rather than met by surprise.

## Consequences

**The derivation test grows a second accepted justification**, and must check the view field named
is real - a justification pointing at a field nobody built is the strict rule with extra steps.

**The catalogue can be restored to the predecessor's coverage**, which
[`0065`](0065-the-catalogue-recovers-what-the-rebuild-dropped.md) does. Much of what was lost -
identity, time, `description` - has an object view behind it rather than a rule.

**The object view now constrains the catalogue in both directions.** Removing a field from that
screen may orphan an attribute, and the test will say so. That is the rule working.
