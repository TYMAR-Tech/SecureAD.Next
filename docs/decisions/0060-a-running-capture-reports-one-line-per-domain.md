# 0060 - A running capture reports one line per domain, and errors as they happen

Date: 2026-08-16
Status: Accepted

Sits under [0056](0056-the-visual-language-encodes-three-states.md) and
[0058](0058-a-run-may-be-stopped-and-stopping-it-keeps-nothing.md). Answers `A2` of the
S-44 agenda.

## Context

A capture runs for hours against every domain in a forest. Until now nothing decided what the
operator sees while it does, which left the choice between a screen that says nothing until it
finishes and one that reports every internal step.

The predecessor published progress at three levels, and the owner ran it in production:

- **the run** - its state, total domains, completed domains, elapsed time
- **each domain** - pending, capturing, complete, failed or cancelled; the module currently running;
  and running counts of objects, security descriptors and group edges captured
- **each module within a domain** - items processed, items total where known, and an error count

Three levels was more than the screen needed and less honest than it looked, because the module
level speaks the product's internal vocabulary rather than the operator's.

## Decision

**A running capture shows two things: a line for the run, and a row for each domain.**

**The run line answers "will this finish".** Domains completed out of the total, and time elapsed.

**Each domain row answers "how is this one going".** Its state - waiting, being read, done, failed -
and nothing that requires knowing how capture is built to interpret.

**The module level is not shown.** *"Module 4 of 9"* and *"group edges captured"* are the product
describing its own construction. They tell an operator that something is happening without telling
him whether it is going **well**, which is the only question the screen is there to answer. They are
also the numbers least likely to be noticed when wrong, because nothing downstream reads them.

**The per-domain object counts are not shown either**, for the same reason: a number climbing is
motion, not progress, and an operator cannot tell a healthy count from an unhealthy one without
knowing the forest's size in advance.

**Errors are shown as they happen, counted per domain.** This is the one thing lifted up out of the
module level, because it changes what the operator does. *"Still reading, twelve errors so far"* and
*"still reading"* are different situations, and the first is one where he may want to stop -
which [`0058`](0058-a-run-may-be-stopped-and-stopping-it-keeps-nothing.md) now lets him do. An error
count that only appears with the finished run arrives after the decision it was needed for.

**A domain with errors is not thereby failing.** Under
[`0056`](0056-the-visual-language-encodes-three-states.md) the count is a fact about the row, not a
verdict on it; a domain reading normally with a handful of unreadable descriptors is a different
state from one that could not be read at all, and the screen must not collapse them.

## Consequences

**Progress is display only, and nothing may be judged from it.** No count on this screen reaches a
bundle, a report or a comparison. It exists for the duration of the run and then it is gone -
including when the run is stopped, which by `0058` leaves nothing at all.

**The row must distinguish "not started" from "started and quiet".** A domain waiting its turn and a
domain being read that has produced nothing yet look identical if the row carries only a state word,
and they are the product's own *found nothing* versus *could not compute* in miniature.

**What is undecided.** Whether the operator can see *which* error, or only how many; and how the
screen behaves when [`0041`](0041-capture-reads-domains-in-parallel.md)'s parallel reads mean six
rows are active at once. Both are questions about how it feels on screen and are better answered
against a running window than in advance.
