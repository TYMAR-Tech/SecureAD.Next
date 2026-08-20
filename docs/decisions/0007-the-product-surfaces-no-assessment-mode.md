# 0007 - The product surfaces no assessment mode, because it captures only one

Date: 2026-08-08
Status: Superseded by [0031](0031-there-is-no-assessment-mode.md). There is no assessment mode:
nothing records one, nothing reads one, and nothing compares on one. Both grounds this record gave
for keeping the value have gone.

## Context

An earlier design offered two kinds of capture, and every run therefore carried the mode it was
taken in. One of those kinds was removed. The field survived: capture writes the constant
`"Security"` into `run.assessment_mode` and into `dim_database_metadata`, compare reads it, and the
Run Library displayed it in a column beside the domain, the date and the run state.

Those neighbouring columns vary between runs, and a column that sits among them is read as varying
too. An auditor looking at the library concluded that this run was captured in Security mode and
that another one might not have been. Nothing in any bundle this product can write supports that
reading. The same constant appeared a second time in the recent-runs list on the home screen.

A constant presented as a measurement is worse than no column at all: it invites a conclusion about
the evidence that the evidence does not carry.

## Decision

The assessment mode is not shown to a user anywhere.

It remains recorded in the bundle and remains readable, because it is evidence of what the capture
was and because compare refuses to compare runs whose modes differ. It is a fact about the
artefact, not a property offered to the reader for interpretation.

Where the mode cannot be read from a bundle, it is `"Security"`. The absence of the value is a
failed read, never evidence of a different mode, and nothing downstream may treat a missing mode as
a reason to withhold a capability — a run whose mode did not survive is still grouped with the other
runs of its forest.

## Consequences

Any future second mode is a product change that must add its surface deliberately, with the
question *what does this tell a user that varies?* answered first. The surface cannot reappear by
accident, because tests assert that neither view binds the value.

Nothing is lost from the record: a bundle still states its own mode, and a reader who needs it can
query it.

The mode is not available as a display or grouping input. Anything that needs to distinguish runs
must use something that actually differs between them — forest, scope, coverage, or time.
