# 0068 - A finished run reports with its gaps shown; an unfinished one reports not at all

Date: 2026-08-16
Status: Accepted

Sits under [0002](0002-absent-view-means-degraded-run.md),
[0027](0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) and
[0029](0029-a-run-that-ends-badly-says-so.md). Answers `C3` of the
[S-44 agenda](../next/sessions/S-44-agenda.md) and the format half of `B4`.

## Context

Nothing decided how much missing coverage was too much to report on. The predecessor answered it and
the answer held up: `OutputEligibilityEvaluator` sat in front of every export and applied two
different rules to two different situations, and the distinction between them is the point.

## Decision

**A run that did not finish produces no report and no export.** The attempt is refused with a
message. There is nothing to report on: an unfinished run has no evidence, and a document built from
part of one would be a document whose gaps nobody can enumerate, because the run never got far
enough to know what it was missing.

**A finished run with incomplete coverage reports, and the report carries the gaps.** It is never
blocked. A forest where two organisational units could not be read is still a forest worth
reporting on, and refusing to say anything is worse than saying it with the holes named - the
customer's alternative to an annotated report is no audit at all.

**The coverage warning is part of the report, not a dialog before it.** A warning an operator
dismisses on screen does not travel with the document, and the document is what reaches the auditor.
Whatever a report says about its own gaps must survive being emailed.

**There is no threshold.** Not *"blocks above 20% missing"*. A threshold invents a number nobody can
justify and creates a cliff where a report that would have been useful is refused, while implying
that anything under the line is fine. Coverage is stated, always, whatever its level, and the reader
judges.

**The formats are CSV, JSON, HTML and PDF.** The first three were the predecessor's. PDF is added
because an auditor asks for it, and a document produced for an auditor that has to be converted by
hand before it can be filed is a document that will be converted badly.

## Consequences

**"Finished" needs a precise meaning**, from [`0028`](0028-one-run-state-vocabulary.md)'s vocabulary.
A degraded run is finished. An interrupted one is not. Nothing else may define this test.

**This is the same rule as gate 4, at document level.** *Found nothing* and *could not compute* must
render differently - and a report that omits its coverage is the second wearing the clothes of the
first. A section stating what was not read is therefore not an appendix; it is what makes the rest
of the document honest.

**PDF is a dependency the product does not have.** It is the only format here that cannot be written
with what is already in the tree, and picking how is an engineering decision for the session that
builds it.

**What a report is *for* is still open** - `B4` of the agenda. The owner's position on 2026-08-16:
*"the reports I had were done fast and not well thought out"*, and the audience question is deferred
to the session that builds them. This record governs **when** a report may be produced and in what
formats, not what it says.
