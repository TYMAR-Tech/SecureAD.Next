# 0058 - A run may be stopped, and stopping it keeps nothing

Date: 2026-08-16
Status: Accepted

Sits under [0028](0028-one-run-state-vocabulary.md) and
[0029](0029-a-run-that-ends-badly-says-so.md). Answers `A1` of the
[S-44 agenda](../next/sessions/S-44-agenda.md).

## Context

A capture reads every domain in a forest and runs for hours. An operator who starts one at the wrong
moment - the wrong forest, the wrong time of day, a controller he has just realised is mid-patch -
has no way to take it back, and the machine is occupied until it finishes.

The predecessor published progress at three levels and carried `Cancelled` states on both its shard
and module lifecycles, so stopping was possible there. What it did with the partial evidence
afterwards is not what this record decides; what it decides is that there is nothing to do with it.

Three shapes were considered: no stop at all, stop and discard, and stop while keeping what had been
read as a deliberately truncated run.

## Decision

**An operator may stop a capture that is in progress, and stopping it keeps nothing.**

**A stopped run leaves no openable evidence.** Not a shorter run, not a run with fewer domains, not
a bundle marked partial. The half-read data is discarded.

The reason is the product's oldest rule: *found nothing* and *could not compute* must never render
alike. A kept half-run is the most convincing way to break it. It would be openable, and therefore
comparable, and therefore reportable - and a domain that was never reached would sit beside a domain
that was read and found clean, in a document handed to an auditor. Every screen downstream would
then need to carry the question *"was this run whole?"*, forever, to stay honest. Refusing to keep
the evidence removes that question instead of answering it in thirty places.

**The cost is accepted and it is real.** An operator six hours into an eight-hour capture who stops
it loses six hours. That is the right trade against a class of quiet wrong answers, and it is a cost
he chooses knowingly at the moment he presses the button.

**Stopping is a deliberate act and the product treats it as one.** It is confirmed before it takes
effect, and the confirmation states plainly that the work so far is lost. It is not a failure and it
is never reported as one - [`0029`](0029-a-run-that-ends-badly-says-so.md) governs runs that end
badly, and this is not one of those.

## Consequences

**The run state vocabulary needs a term for it**, under
[`0028`](0028-one-run-state-vocabulary.md). A stopped run is neither complete, nor degraded, nor
failed. Whatever it is called, it is a state a run passes through on its way to leaving nothing
behind, not a state a stored run rests in.

**Comparability is not affected.** [`0026`](0026-one-answer-to-whether-runs-may-be-compared.md) does
not need a new outcome, because there is no artefact to compare. This is the direct benefit of
discarding rather than keeping.

**Capture must be able to stop promptly and clean up after itself.** A stop that takes twenty
minutes to take effect is not a stop, and partial evidence left on disk after one is the outcome
this record forbids, arrived at by accident.

**A stopped run does not appear in the run library.** Not a line, not an abandoned entry with a time
against it. The run library holds evidence, and a stopped run produced none; a row that can never be
opened is furniture that every future screen has to decide how to draw and every future count has to
decide whether to include. An operator who stops a run and starts another sees one audit, because
one audit happened.

**A cancellation marker is written for diagnostics, outside the run library.** Somewhere the library
does not read, so it can never become a row. It exists to answer *"what happened to that run"* when
something goes wrong with the cancelling itself - not to be evidence, and not to be presented to an
operator as a run. This amends [`0029`](0029-a-run-that-ends-badly-says-so.md), which placed the
marker for a cancelled run in the bundle directory the library enumerates.

**Where that marker lives, and what else the product logs, is undecided.** The owner's position on
2026-08-16 is that logging around run endings needs thought of its own. This record requires only
that the marker exist and that it be somewhere the library cannot mistake for a run.
