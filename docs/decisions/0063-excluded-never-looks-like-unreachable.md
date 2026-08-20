# 0063 - A domain left out by choice never looks like one that could not be reached

Date: 2026-08-16
Status: Accepted

Draws the seam between [0052](0052-the-domain-is-the-only-unit-of-scope.md) and
[0054](0054-a-domain-with-no-candidates-is-an-attested-exclusion.md), raised as open by both
[domains-we-skip](../areas/domains-we-skip.md) and
[which-controller-we-read](../areas/which-controller-we-read.md). Answers `A6` of the
S-44 agenda.

## Context

Two domains can end a run with no data behind them. One was excluded by the operator under
[`0052`](0052-the-domain-is-the-only-unit-of-scope.md). The other had no reachable controller and
became an attested exclusion under
[`0054`](0054-a-domain-with-no-candidates-is-an-attested-exclusion.md).

By the letter of the records both are attested exclusions, and the shared word made it look as
though they could share a representation. Neither area file could resolve it, and each pointed at
the other.

## Decision

**They are two different events and the product never renders them alike.**

**One is a decision, the other is a fact about the network.** An operator who chose to leave a domain
out knows it is out. An operator whose forest contained a domain nothing could reach has learned
something about his estate, and it may be the most important thing the run found - a domain with no
reachable controller is either a network problem, a trust problem, or a domain that is not there any
more, and all three are worth his attention.

Collapsing them hides the second inside the first. A screen reporting *"3 domains not covered"* over
a run where the operator excluded one and two were silently unreachable tells him what he already
knew and conceals what he did not.

**This is the same rule the product applies everywhere else**, stated in
[`0026`](0026-one-answer-to-whether-runs-may-be-compared.md) and enforced by gate 4: *found nothing*
and *could not compute* must never render identically. A chosen exclusion is *we did not look*. An
unreachable domain is *we tried and could not*.

**The distinction holds wherever either appears** - the coverage summary, the run's own record of
what it covered, a report, and the comparison refusal under
[`0061`](0061-runs-of-different-scope-are-not-comparable.md). It is not a nicety of one screen, and
a surface that shows only the total of uncovered domains has lost it.

**What `0054` decided still stands.** An unreachable domain still produces an attestation, so the
run states plainly that it was not covered rather than passing over it. That record governs how the
absence is *recorded*; this one governs that it is never confused with a choice.

## Consequences

**Coverage carries the cause, not just the gap.** Whatever records that a domain was not covered
records *why* it was not, drawn from a closed set, and every reader of coverage can tell the two
apart without going back to another table.

**"Not covered" is not a count the product may report on its own.** Any total of uncovered domains
is broken down by cause where it is shown, or it is not shown.

**The New Audit screen inherits this too.** A domain that preflight found unreachable and a domain
the operator has ticked out are different rows with different marks, before the run starts.

**A domain can be both**, and the product must decide which it says. An operator may exclude a
domain that would also have been unreachable. The exclusion is what governs the run - the product
never looked, so it cannot claim the domain was unreachable. Recorded here because the case is
certain to arise and the wrong answer is the flattering one.
