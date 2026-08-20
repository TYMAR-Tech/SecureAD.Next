# 0010 - The rule catalogue is data; the rule logic is code

Date: 2026-08-09
Status: Accepted

## Context

Rule metadata moved out of C# in April 2026, when `BuiltInRules.cs` held 571 lines of object
initialisers. The move reduced it to 13 and put the seven metadata fields in an embedded
`rules.yaml`. Severity followed later, so the yaml became the single source for what a rule is
called, how bad it is, and whether it runs at all.

None of the detection logic moved, and none was ever intended to. A rule fires when an
`IRuleEvaluator` says so, in C# and SQL. The rules that reduce to a declaration already do — four
distinct rules are one call each to `RuleEvaluatorHelpers.EvaluateControlEdgeRule`, naming a control
type and a filter — and that declaration has a compiler and a debugger behind it, which a
configuration format would not.

What has become confused is the yaml itself. Two of its seven fields decide behaviour and five are
presentation copy the run never reads. Changing a severity and fixing a typo in remediation text are
the same edit to the same file, and arrive at review indistinguishable.

## Decision

Rule identity, severity and enablement are data. Rule detection is code.

The behavioural fields — id, severity, enabled — live in their own file, separate from name,
description, remediation, MITRE mapping and tags. A change to what the product reports is therefore
a change to a file whose name says so.

Detection is not expressed in a configuration format or a rule language. Where rules share a shape,
they share an evaluator function and differ by its arguments.

A rule is only real when the catalogue, an evaluator, a coverage requirement and a written
specification all agree, and that agreement is asserted by tests rather than maintained by care.

## Consequences

Adding a rule touches two catalogue files instead of one. The parity tests already fail the build on
a half-added rule, so the cost is a second edit rather than a new class of defect.

Reviewers can be asked to treat one small file as security-relevant. That is only worth doing
because the copy it no longer contains is the part that changes most often.

There is no path for a customer to supply rules, and the design continues to exclude one. Anything
the product reports is something the product can be held to.

Specifications in `docs/rules/` become load-bearing rather than descriptive, because a rule without
one is now incomplete.
