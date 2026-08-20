# 0031 - There is no assessment mode

Date: 2026-08-12
Status: Accepted

Supersedes [`0007`](0007-the-product-surfaces-no-assessment-mode.md) entirely.

## Context

[`0007`](0007-the-product-surfaces-no-assessment-mode.md) removed the assessment mode from every
screen, and kept the value in the bundle on two grounds: that it is evidence of what the capture
was, and that comparison refuses to compare runs whose modes differ.

Neither ground survives.

The mode was a leftover. An earlier design offered two kinds of capture; one was deleted, and the
field stayed behind writing the constant `"Security"` into every bundle. `0007` correctly stopped
showing a constant to a user, and then preserved the constant because it looked like evidence.

**It is not evidence.** A field that has one value in every artefact this product can produce
records nothing about the artefact. It answers no question a reader could ask, because there is no
second answer for it to distinguish.

**And nothing compares on it.** The rebuild has no assessment mode anywhere -
`git grep -in "assessment"` over `next/` and `docs/next/` returns nothing.
[`0026`](0026-one-answer-to-whether-runs-may-be-compared.md) made a single component the only place
that answers *may these runs be compared*, and its closed set of outcomes, revised by
[`0027`](0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md), has no member for a
mode mismatch and never had one. So `0007` asserts a refusal that no code performs and that the one
component entitled to perform it cannot express.

This is the same failure `0027` recorded: a record reasoning from a mechanism the product no longer
has. It was found on 2026-08-12 by reading every record against every other.

## Decision

**There is no assessment mode.** Nothing records one, nothing reads one, and nothing compares on
one. The concept is not part of this product.

`0007`'s instruction to hide the mode is not carried forward, because there is nothing to hide.

**If a second kind of capture is ever introduced, it is a product change requiring its own record**,
and that record must answer `0007`'s question before adding any surface: *what does this tell a user
that varies?* It must also decide, explicitly, whether the difference is a reason to refuse a
comparison - which means adding a member to the comparability outcomes, where the compiler will then
name every place that must handle it.

## Consequences

A bundle carries one less field, and no reader needs a case for it.

`0007`'s guard against the surface reappearing goes with it, and that is a real loss of a small
protection. It is accepted because the guard defended a column showing a value that will no longer
exist, and a test asserting that nothing displays a field the schema does not have is a test
measuring nothing - which this repository already treats as worse than no test at all.

**The word *scope* in `0007`'s last line was already dead when it was written.** It says anything
distinguishing runs must use *"forest, scope, coverage, or time"*, and scoped capture had been
removed on 2026-08-02. Coverage now varies only two ways, per `0027`. What actually distinguishes
two runs of this product is the forest, the coverage, and the time.
