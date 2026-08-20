# 0005 - A withheld count is withheld at the widest scope that shares its verdict

Date: 2026-08-07
Status: Accepted

## Context

[0004](0004-unknown-counts-name-the-failed-phase.md) settled that a count the run cannot vouch for
renders as `unknown` naming the phase, and that this is decided per count rather than for a summary
as a whole. That is enough while each count appears once.

A table repeats a count. The forest report's Domain Breakdown states a finding count per domain, so
one unvouchable count becomes as many unvouchable cells as there are domains. Applying 0004
literally puts the same sentence in every row.

The choice is not obvious from the code, because all three readings are defensible: withhold the
cell, withhold the row, or withhold the table.

## Decision

A withheld count is withheld at the widest scope over which the verdict is identical, and the reason
is stated once for that scope.

Phase verdicts are properties of the run, not of a domain, an object or any other row key. So a
count repeated down a column is withheld as a **column**: every cell reads `unknown`, and the phase
is named once beneath the table rather than in each cell.

Neighbouring columns keep printing when they depend on different phases. The Domain Breakdown's
object and ACE counts are read from captured facts and owe nothing to findings derivation, so a row
with an unknown finding count still states them.

## Consequences

The reader sees a table with one column visibly withheld and the rest intact, which is a truer
picture than a blanked row and far less noise than a repeated sentence.

Withholding the whole table is forbidden, because it would discard measurements the run can stand
behind for the sake of one it cannot — the same reasoning that makes 0004 prefer `unknown` to
omitting a summary.

This is only correct while the verdict really is uniform across the rows. A count whose
trustworthiness varies per row — per domain, say, if phases were ever recorded per domain — would
have to be withheld per cell, and the reason would have to travel with the cell.
