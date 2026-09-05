# 0096 - Effective permissions are shown object-first and principal-first, over one edge set

Date: 2026-09-05
Status: Accepted.

Settles `P-71`. Corrects the row's premise: the row said nothing computes effective permissions
today, and something does.

## Context

**The computation exists.** `next/src/SecureAD.Evidence/EffectiveAccessCalculator.cs` returns an
`EffectiveAccessResult` with an outcome and an `IsComplete` voucher, applying denies before allows
in canonical order and keeping inheritance. `SEC-060` consumes it today
(`EffectiveAccessCalculator.Over(permissions, objectTypeGuid: null)`), and it deliberately keeps
"no readable descriptor" apart from "grants nothing" - on a production domain 19,927 of 100,000
objects had no readable descriptor, and reporting those as safe would be the one thing an audit tool
must never do.

So `P-71` is a **presentation** question, not a computation one. That is what was put to the owner.

**Why it gates stage 6.** A control edge *is* an effective-permission claim. Deciding afterwards how
it is presented means rebuilding what stores it.

## Decision

**Both views, built over one stored edge set.**

- **Object-first**: pick an object, see every principal that can take it over and by what right.
  This is the shape an AD administrator already knows from the Windows *Effective Access* tab.
- **Principal-first**: pick a principal, see every object it can take over. This answers *what does
  this service account actually reach*, which the object-first view cannot.

**The edge set is written once and each view is a query over it.** This is the whole reason the
second view is cheap, and the reason the two can never disagree: there is no second computation to
drift. A view that needs a fact the edge set does not carry is a change to the edge set, not a
second calculation beside it.

## Consequences

**Every view inherits the calculator's silences.** An object whose descriptor could not be read is
shown as unanswered in both views and never as "nobody can take it over".

**Filters on these views are permitted** under [0092](0092-a-view-filter-is-not-a-change-to-the-catalogue.md),
under its three conditions. The default filter that
[0098](0098-a-control-edge-is-expected-or-unexpected.md) sets is exactly such a filter.
