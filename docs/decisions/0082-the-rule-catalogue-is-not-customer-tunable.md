# 0082 - The rule catalogue is not tunable by a customer

Date: 2026-08-21
Status: Accepted

Answers the question [0066](0066-a-finding-is-called-a-finding.md) raised and left open.

## Context

`0066` fixed severity to the rule card and recorded that whether a customer may tune the catalogue
at all was genuinely open, because the predecessor's implementation went unused.

It went further than unused. The predecessor built a policy carrying allowed principals, severity
overrides and per-rule hop limits, with a loader, an evaluator and an audit log beside it - roughly
1,380 lines. **None of it ever ran.** The generation path constructed an empty policy and never
consulted the loaded one, and the typed matcher beside it had no caller anywhere.

Its tests all passed, because they built the components directly and never asserted that anything
in production reached them. There was no `[Obsolete]`, no TODO and no failing test to notice.

## Decision

**A customer cannot tune the catalogue.** No rule is disabled, no rule is added, no severity is
changed, and no principal is exempted by policy.

**Accepting a finding remains the way to say "this one is fine here"**, per `0066`. It is per
finding, it carries a reason and a name, and it stays visible.

## Consequences

**One evaluation path.** No policy load order, no precedence between an override and an
acceptance, and no audit trail for changes that cannot be made.

**It forbids a quietly disabled rule.** A rule switched off by configuration reports nothing and
looks identical to a rule that found nothing, which is the failure `0056` exists to prevent.

**Reopening this needs a new record**, with the argument above answered rather than a default
flipped.

**A separate lesson stands regardless of this decision:** a subsystem with a public entry point
needs a test asserting that some production path reaches it. Unit tests measure whether a
component works, not whether anything calls it.
