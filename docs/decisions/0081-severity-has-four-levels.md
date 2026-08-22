# 0081 - Severity has four levels

Date: 2026-08-21
Status: Accepted

Completes [0066](0066-a-finding-is-called-a-finding.md), which fixed severity to the rule card
without saying what values exist.

## Context

The predecessor defined five levels: `Info`, `Low`, `Medium`, `High`, `Critical`.

Across the sixty-two rule cards, four of those are used. **`Info` is not used once.** A level that
survived sixty-two attempts to find a use for it is not being kept for a rule that exists; it is
being kept in case one turns up.

An unused level is not free. It sits in a legend, in a filter, in a sort order and in a colour
scheme, and every reader has to learn a word that never appears beside a finding.

## Decision

**Severity has four levels: `Critical`, `High`, `Medium`, `Low`.**

**`Info` is not carried.** A rule with no security consequence to state is not a finding, and the
product has other ways to tell an operator a fact about the forest.

## Consequences

**A rule must sit at one of four levels or not ship.** A rule whose author reaches for `Info` is a
rule that has not decided what it is for, and that argument happens before the rule lands rather
than after it is on a screen.

**The level stays catalogue data**, per `0066`, so this changes what values are legal and nothing
about where they live.

**This record does not decide how a level is shown.** Two of the visual marks are already spoken
for by capture-side states, so the mapping from level to colour is a separate question and is not
settled here.

**Reopening `Info` requires a rule that needs it**, named, not a general argument that some future
rule might.
