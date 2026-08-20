# 0004 - A count the run cannot vouch for renders as unknown, naming the phase

Date: 2026-08-07
Status: Accepted. *Signing* was corrected to *sealing* below, per
[0030](0030-the-product-produces-sealed-evidence-never-signed.md).

## Context

The exported forest report opens with an executive summary of counts — findings, control edges,
escalation paths. Those counts are read with a helper that returns `0` when the query throws, so
on a run whose analysis did not finish the summary states three precise zeros directly beneath a
banner warning that sections may be missing. A reader weighing a vague warning against precise
numbers believes the numbers.

A report is also the artefact most likely to travel. It gets forwarded to someone who never opened
the tool, never saw the banner in context, and has no way to tell a measured zero from a failed
query.

There are two ways to reach a false zero, and they need different detection:

- **The view is missing**, because the phase that creates views failed. The query throws and the
  helper swallows it.
- **The view exists but its table was never populated**, because a later phase failed. The query
  succeeds and honestly returns `0` from an empty table.

Checking whether a view exists catches only the first. The run already records the second: every
phase writes its own outcome, and the health verdict names the phases that failed.

## Decision

A count the run cannot vouch for is rendered as **unknown**, in the place the number would have
occupied, naming the phase responsible — for example *"Findings: unknown — control edge derivation
did not complete."*

This is decided **per count**, not for the summary as a whole, and it is keyed off the **phase
verdict**, not off whether a view exists.

The report is still generated. Unlike re-analysis, which refuses an incomplete source because it
ends by sealing new evidence (see [0003](0003-refuse-to-reanalyse-an-incomplete-capture.md)), a
report only renders evidence that already exists, and partial evidence is still worth reading.

## Consequences

Counts that are trustworthy still print, so a run that lost one phase does not lose its whole
summary. This is why unknown is preferred to omission: omitting counts safely would mean omitting
all of them, since a summary cannot show which of its numbers to believe.

Keying off the phase verdict covers both false-zero modes. Keying off view existence would fix the
louder one and leave the quieter one, which is harder to notice precisely because nothing throws.

The word *unknown* occupies the slot a number would have, so its absence is visible to someone
skimming. A blank or a dash would not be.

The phase name is included because a reader who cannot act on "something failed" can often act on
"escalation path analysis failed" — and because it distinguishes a degraded run from an empty
forest without requiring the reader to already know the difference.
