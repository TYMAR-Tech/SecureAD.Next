# 0079 - A privileged variant of a rule escalates, and both findings stand

Date: 2026-08-21
Status: Accepted

Sits under [0010](0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md),
[0023](0023-a-finding-has-a-stable-identity.md) and
[0066](0066-a-finding-is-called-a-finding.md).

## Context

Several rules come in pairs: one names a condition, the other names the same condition on a
privileged account. The kerberoastable pair and the AS-REP roastable pair both do this, and in
both the privileged member is `Critical` where the base is `Medium`.

The unconstrained delegation pair does not. `SEC-010` and its privileged variant `SEC-131` are
both `High`, so the variant escalates nothing and a reader cannot tell from severity which of two
findings to attend to first.

The pairs also overlap by design: a privileged account meeting the condition produces two
findings, because the base rule carries no privilege filter. This was read as a duplicate during
review. It is not - it is the shape two pairs already use.

## Decision

**A privileged variant carries a higher severity than its base.** `SEC-131` becomes `Critical`.

**Both findings stand.** The base rule is the complete inventory of a condition; the variant is
the subset that cannot wait. Neither removes the other. Nothing in the engine deletes a finding
another rule produced: a finding that disappears when a second rule fires leaves nothing at all
behind on the day that second rule is the one that fails.

**The relationship is catalogue data.** A rule card names the rule it is the privileged tier of.
It is read for ordering and display and is never a computed property of a finding.

**Acceptance is not inherited between them.** Accepting the base says this account legitimately
needs the condition; accepting the variant says a *privileged* account does. The second is the
larger claim and is answered on its own.

## Consequences

**Nothing merges.** One finding cannot span two rules, because `0023` identifies a finding by its
rule, its subject and the object it is about.

**An operator who judges a privileged account acceptable answers twice.** That is the price of
this decision and it is deliberate - the second answer asserts more than the first.

**Severity stays readable off the card**, as `0066` requires. A rule computing its own severity
from runtime privilege would move it somewhere the catalogue cannot show.
