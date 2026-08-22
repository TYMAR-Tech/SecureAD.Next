# 0083 - A rule declares the data it depends on, and an undeclared rule fails the build

Date: 2026-08-21
Status: Accepted

Makes [0056](0056-the-visual-language-encodes-three-states.md) checkable per rule rather than only
per run.

## Context

The predecessor recorded every rule's inputs in one hand-maintained dictionary of sixty-four
entries, held in the findings service and separate from the rules themselves. The evaluators did
not declare their own inputs.

A rule added without an entry fell through to a heuristic default of "objects", and was then
stamped **coverage-complete on a bundle where its actual inputs were never captured**. The
predecessor's own review called this the single most consequential structural problem in the
branch, and described it exactly: not a missing feature, but a wrong answer stated confidently.

The same shape is already present in the catalogue this product inherits. The privileged-delegation
rule decides whether an account is privileged by walking the group-membership closure, and does not
declare that closure as an input. A run that captured memberships only in part would report that
rule as clean.

## Decision

**A rule declares the data it depends on, in the same place the rule is defined.**

**The coverage verdict reads that declaration** rather than a separate list maintained by hand.

**A rule that declares nothing fails the build.** It does not fall back to a default, and it does
not default to complete.

## Consequences

**Every rule pays a declaration.** That is the cost, and it is paid by the person best placed to
know the answer, at the moment they are writing the rule.

**A central map of rule inputs may still exist as a test fixture**, checked against the
declarations. It is never a runtime input again.

**It forbids the silent default.** A rule whose inputs are unknown produces no verdict at all,
which is loud, rather than a clean verdict, which is not.

**A rule cannot be added by an author who has not thought about what it reads**, because the build
will not accept one. That is the intended friction.
