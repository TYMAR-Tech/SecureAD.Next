# 0010 - The rule catalogue is data; the rule logic is code

Date: 2026-08-09
Status: Accepted. **The mechanism described below is the predecessor's and no longer exists**;
corrected by the amendment at the foot of this record, 2026-08-26. The decision itself — that
detection is code rather than configuration, and that the rule set is not the customer's — stands and
is reinforced by [0082](0082-the-rule-catalogue-is-not-customer-tunable.md).

## Context

Rule metadata moved out of C# in April 2026, when the predecessor's `BuiltInRules.cs` held 571 lines
of object initialisers. The move reduced it to 13 and put the seven metadata fields in an embedded
predecessor `rules.yaml`. Severity followed later, so that yaml became the single source for what a
rule is called, how bad it is, and whether it runs at all.

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

---

## Amendment, 2026-08-26 — the mechanism was the predecessor's

**Everything above about *how* describes the previous product.** The `rules.yaml` catalogue, the
split into two catalogue files, `IRuleEvaluator`, `RuleEvaluatorHelpers`, the parity tests and the
coverage requirements are all the predecessor's, and none of them exists in this tree. The
consequence written above — *adding a rule touches two catalogue files instead of one* — is not true
here and would send anyone who read it looking for files that are not there.

**What this product did at the 2026-08-26 amendment.** A rule was an `IRule` in
`SecureAD.Evidence/Findings`, carrying
its own `RuleDefinition` — identity, severity, version, the classes it judges and the attributes it
reads. The set that runs is a literal list in `RuleCatalogue.All`, which is deliberate:
`0082` keeps the rule set out of the customer's hands, and a set assembled by reflection is a set
nobody can read off the page. There is no catalogue file of any kind.

**Ownership correction, 2026-08-28.** Executable `IRule`, `RuleVerdict`, rule implementations and
the literal `RuleCatalogue` now live in `SecureAD.Judgement`, the layer that coordinates captured
evidence and reusable derivation. Passive `RuleDefinition`, finding identities and typed finding
evidence remain in `SecureAD.Evidence.Findings`. The decision is unchanged: detection is code and the
customer cannot tune the catalogue. Only the project owning executable policy moved, so Evidence
does not need an upward dependency on Derivation.

**The decision itself is untouched by this.** Detection is code, not a configuration format or a rule
language; a rule's identity and severity are declared rather than computed; and nothing lets a
customer supply or tune a rule. All three hold, and hold more simply than they did — with no yaml,
the question of which fields are behavioural and which are presentation copy does not arise.

**The last consequence is now false and worth naming.** `docs/rules/` is *not* load-bearing here. Its
sixty-six cards are the predecessor's, quarantined on 2026-08-26 under `P-101` and marked as such on
every file, because they describe an architecture this product does not have. What a rule is here is
layers/judgement/what-a-finding-is.md, and that page is
held to the code by a gate. This amendment exists because
`PredecessorMaterialGateTests` — written to stop exactly this contamination spreading out of
`docs/rules/` — failed on this record within minutes of being written.
