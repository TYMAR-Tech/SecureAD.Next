# 0093 - An export states what it contains

Date: 2026-09-03
Status: Accepted.

Sits beside [0092](0092-a-view-filter-is-not-a-change-to-the-catalogue.md), whose second condition
this record states in full so that it binds every export rather than only the ones that have a filter
today. Rests on [0086](0086-a-qualified-statement-beats-silence.md) and on the second of the five
commitments: a gap is a fact about the capture, never about the forest.

## Context

**The predecessor's LAPS export is the worked example, and it failed in both directions at once.**
Its grid offered filters on domain, tier, status and health. Its export ran:

```sql
SELECT <columns> FROM v_grid_laps_status ORDER BY computer_name ASC
```

No filter clause. So an operator who filtered to *Missing* and pressed export received **every
computer in the forest, including the healthy ones** - in a file named `computers_no_laps.csv`, from
a dialog titled *Export Computers Without LAPS*.

**Both halves of that are wrong and they are different faults.** The file did not honour the filter,
and it did not say that it had not. Its name asserted a subset it did not contain. A recipient who
opened it and counted rows would have concluded the estate was far worse than it is; a recipient who
trusted the title would have concluded the opposite.

**An exported file outlives the screen that produced it.** It is mailed, filed, attached to a report
and read months later by somebody who never saw the grid, never set the filter, and has no way to ask
what was on screen at the time. Everything the screen knew and the file did not is lost silently.

**This is the shape of failure this product exists to avoid**, stated in the second commitment: a
partial view must never read as a complete one. `0068` already refuses to report an unfinished run
partially, for the same reason. An export is the same problem one layer out.

## Decision

**An export states what it contains.** Every exported or printed artefact carries, in the artefact
itself and not only in its filename:

1. **What it is** - the run it came from, and what was exported.
2. **How many rows, out of how many** - *312 of 4,312*.
3. **Every filter in force**, named with its value, or an explicit statement that none was applied.

**An export either honours the active filter or does not offer one.** Silently ignoring a filter is
prohibited, and so is silently applying one.

**A filename is not a statement.** It may describe the export, but it never substitutes for the
three items above, because a file is renamed by the first person who saves it.

**This binds every export the product grows**, including findings, inventory grids, reports and any
future comparison output. It is not a property of one screen.

## Consequences

**Every export gains a header**, and every export path has one more thing to get right. That cost is
accepted: it is small, it is paid once per export, and the failure it prevents is a customer making a
security decision from a file that misrepresents its own contents.

**The unfiltered case is not exempt.** *No filter applied* is stated explicitly rather than left to
silence, because absence of a statement is what the reader cannot distinguish from absence of a
filter. This is [0086](0086-a-qualified-statement-beats-silence.md) applied to a file.

**A test can hold this**, because it derives what it expects from the export code: change the columns
or the filter handling and the header changes with it. It is not a prose gate.

**The predecessor's export is not ported.** Its query, its naming and its filter handling are all
superseded here, and the LAPS inventory grid specified on 2026-09-03 is the first thing built under
this record.
