# 0055 - The PDC emulator is established at preflight, not at discovery

Date: 2026-08-15
Status: Accepted

## Context

[`0050`](0050-the-candidate-list-comes-from-the-configuration-partition.md) ranks a domain's
controllers by site, then by whether the controller holds an operations master role, then lexically
by host name. The middle criterion exists for one machine above all: the PDC emulator carries time
synchronisation, password change chaining, account lockout evaluation and Group Policy editing for a
whole domain, and a forest-wide audit is a read measured in hours. Pointing one at the PDC emulator
is the single clearly bad choice available to selection.

`0050` also states, and this is the part that turned out to matter, that **discovery contacts
nobody**: every controller holds a full replica of the configuration partition, so one connection
yields the topology of the entire forest.

Those two commitments do not both survive contact with where the roles are recorded. A role is not
an attribute of a controller. It is a single `fSMORoleOwner` attribute on the object the role
governs:

- **Schema master** - the schema naming context head
- **Domain naming master** - `CN=Partitions` beneath the configuration partition
- **PDC emulator** - each domain's own naming context head

The first two live in partitions every controller in the forest replicates, so both are answered by
the connection discovery already has open. The third does not. A controller of one domain does not
hold another domain's naming context head, and referral chasing is off for the paging reason
`CaptureSearchRequestFactory` records - so asking it produces a failure rather than a quiet answer
from a machine nobody chose.

Establishing every domain's PDC emulator at discovery therefore costs **a connection per domain,
paid before anything is on screen**. Measured against this codebase's own settings, that is two to
five seconds in a healthy forest, and up to thirty seconds for each domain that is firewalled or
decommissioned-but-still-registered - the ladder tries four rungs at a ten-second timeout each.
`0050` already warns that the candidate list *"describes controllers that are registered, not
controllers that are running"*, so the slow case is the expected one rather than the unlucky one.
The cost lands hardest in exactly the broken forests where an operator is least willing to wait.

## Decision

**Discovery reads the two forest-level roles and asks no domain about its PDC emulator.** Both
forest roles are free on the connection already open, and the claim that discovery contacts nobody
is kept intact rather than quietly outlived.

**A domain's PDC emulator is established during preflight.** Preflight already opens a connection to
each domain's chosen controller, so the read is one extra base request on a connection that exists,
and costs no connection of its own.

**Selection pins provisionally, and re-pins where preflight proves the pinned controller is the PDC
emulator.** Where a same-site alternative exists it is chosen and that domain is preflighted again.
Where none exists, the run proceeds against the PDC emulator and **says so**, because a slow audit
an operator was warned about is a different thing from a slow audit nobody explained.

**Not yet established is a state of its own, and never renders as "holds no role".** This is the
whole point of the record. A ranker that reads an unasked question as a clean answer sorts the PDC
emulator equal with every other controller in its domain, and may pin the audit straight onto it -
with nothing anywhere recording that it had. `PdcEmulatorKnowledge` therefore carries three values,
not two, and `ForestRoles.IsComplete` states whether every domain was actually answered. This is
[`0002`](0002-absent-view-means-degraded-run.md) applied to a question rather than to a result: an
absence the product created may not be presented as a fact about the forest.

**A PDC read that fails does not fail the run.** The domain is still audited. What is lost is the
ability to keep the audit off that domain's busiest machine, and it is recorded as lost.

## Amendment, 2026-08-16: the prompting is narrowed and says so; the record is not

The clause above - *the run proceeds against the PDC emulator and **says so*** - was written with a
console in mind, where every line costs the reader nothing until he chooses to read it. A window is
not that. The New Audit wizard shows a warning per domain, and the owner's own three-domain lab has
one controller in each domain, so on that forest the original wording produces a warning on every
row of the table, every time, with no action available on any of them.

That is worse than saying nothing. A warning an operator can do nothing about is a warning he learns
to click past, and the next one he clicks past will be one that mattered.

**The prompt appears only where the forest names another controller for the domain** - that is,
only where the operator could have chosen differently. Where a domain has exactly one candidate,
there is nothing to warn about: the run is on the PDC emulator because the forest offers nowhere
else, and reporting a choice that was never available misrepresents what happened.

**The record is unconditional and does not narrow with the prompt.** `preflight.json` carries
`ReadFromPdcEmulator` for every domain it is true of, single-controller or not. The record is a
fact about the audit, kept for whoever reads the bundle six months later and asks why a capture
took nine hours; the prompt is a question put to a person who is standing there and can act. Those
are different obligations and only one of them is conditional.

`DiscoveryWiringTests.ThePreflightFileRecordsThatADomainWasReadFromItsPdcEmulator` is the guard, and
it is deliberately written against a single-controller domain - the exact shape whose prompt is now
suppressed.

## Consequences

The FSMO criterion of `0050`'s ranking is **best-effort for a domain's PDC emulator and exact for
the forest roles**, rather than uniformly exact as `0050` reads. `0050` is not amended: it states
what the ranking is for, and this record states when each input to it becomes available.

Selection and preflight are no longer strictly sequential - preflight now feeds a fact back into
selection. That coupling is real and is the price of not paying a connection per domain up front.

Nothing may restate this record. Rows, comments and notes cite `0055`.
