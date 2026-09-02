# 0092 - A view filter is not a change to the catalogue

Date: 2026-09-03
Status: Accepted.

Sits under [0082](0082-the-rule-catalogue-is-not-customer-tunable.md) and narrows nothing in it. It
answers a question `0082` does not: whether hiding rows on a screen is the tuning `0082` forbids.

## Context

`0082` says a customer cannot tune the catalogue - no rule disabled, no rule added, no severity
changed, no principal exempted by policy - and that **accepting a finding** is how an operator says
*this one is fine here*.

**That is about what the product concludes and stores. It says nothing about what a screen draws**,
and on 2026-09-03 the owner asked for exactly that: filters on the findings and inventory grids so an
operator can control which rows he is looking at. The predecessor had them - `v_grid_laps_status`
filtered on domain, tier, status and health - and they are how a real estate of thousands of machines
is worked at all.

**Without a record, this gets deleted.** A future session finds a filter that suppresses rows, reads
`0082`, and removes it as a violation. That is a predictable loss of a feature the owner asked for,
and it is cheap to prevent now.

**The distinction is real and it is not a technicality.** A tuned catalogue changes what the product
*concluded*: the finding is never written, so no later reader can tell it was possible. A filter
changes only what is *shown right now*: every finding is still written, still stored, still exported,
still counted, and still visible the moment the filter is cleared.

**But a filter can become a tuning knob by accident**, in two ways that have both happened in real
products. It can travel silently into an exported artefact, so a filtered subset is read later as the
whole truth - the predecessor's LAPS export did the reverse of this and was mislabelled either way,
which is the same class of fault. Or it can persist as saved state, so a filter someone set eighteen
months ago silently applies on every open and nobody remembers it exists. That is a disabled rule
wearing a different hat.

## Decision

**A view filter is presentation and is not a catalogue change.** Filters on findings and inventory
grids are permitted, and `0082` does not forbid them.

**Three conditions, and a filter that fails any of them is a tuning knob rather than a view.**

1. **The judgement is unaffected.** Every rule still runs, every finding is still written to the
   store, and the counts a rule reports are the counts it found. A filter never reaches judging.
2. **It never travels silently.** Any exported or printed artefact produced while a filter is active
   states the filter and the counts - *312 of 4,312, filtered by Status = Missing*. An export that
   silently carries a filter is prohibited; so is one that silently ignores it.
3. **It is view state, not policy.** A filter does not survive as saved configuration that
   re-applies unannounced. If a filter is ever made persistent, it must be visible as applied
   whenever it is in force.

**Suppressing a rule in the interface means hiding its rows, never stopping it producing findings.**
An operator may hide a whole rule's output from his view; the store still holds it, an export still
reports it under condition 2, and clearing the filter still shows it.

## Consequences

**The interface may offer filters freely**, which is what makes a grid over a real forest usable and
is what the LAPS work of 2026-09-03 needs.

**Acceptance keeps its meaning and is not replaced.** A filter says *not now*; an acceptance says
*this is fine here*, carries a reason and a name, and stays visible. An estate running Windows LAPS
in legacy emulation mode may hide `SEC-094` while it decides, and accepts those findings when it has.

**Condition 2 is a constraint on the export code**, not on the grid, and it is where this record will
be tested. `0093` states it as its own rule so that it binds every export rather than only the ones
that happen to have a filter today.

**A future session reading `0082` now has an answer** instead of an apparent contradiction, which is
the whole reason this record exists.
