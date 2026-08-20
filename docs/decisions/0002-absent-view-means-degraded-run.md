# 0002 - Missing derived output is a fact about the capture, never about the forest

Date: 2026-08-07
Status: Accepted

## Context

The UI reads most of its grids and dashboard tiles through `v_grid_*` SQL views built by the
derived analysis pipeline. Those views can be absent, because the phase that creates them can
fail while the rest of the run continues.

Readers were each deciding for themselves what to do about that. Some probed for a single view
and returned an empty result if it was missing; others caught the resulting `SqliteException`
and returned zero. Both produce the same output as a genuinely empty forest. In a security audit
tool this is the worst available failure: the answer "no accounts with unconstrained delegation"
and the answer "the analysis that would have found them did not run" appeared identically, as a
reassuring zero, on a report a human was about to act on.

Each of those checks was also a separate guess. None could say *why* the data was missing,
because the probe asked "is this view here?" rather than "did this run finish?".

## Decision

The run records its own completeness once, and readers consult that recording rather than
inferring completeness from the presence of data.

Where derived output is unavailable, the product states that the run is degraded and names the
phases that failed. It never renders unavailable output as an empty result, and never phrases it
as a statement about the directory.

## Consequences

A degraded capture can explain itself: a missing section says which phase failed rather than
showing nothing. Every reader gives the same answer, because there is one answer.

A run that did not record a verdict is treated as degraded rather than as healthy. Not stating
that the analysis finished is not the same as stating that it did, and the weaker reading is the
safe one.

This generalises beyond views. Before adding any guard that returns a default for an absent or
empty result, state what the reader should conclude from it — and if "nothing" could mean either
a fact about the domain or a failure of the query, the guard must distinguish them.
