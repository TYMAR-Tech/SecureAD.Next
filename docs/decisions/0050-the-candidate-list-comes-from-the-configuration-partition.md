# 0050 - The candidate list comes from the configuration partition, and a controller is chosen from it

Date: 2026-08-14
Status: Accepted

## Context

Ledger rows `A3` (name resolution), `A4` (selection policy) and `A5` (discovery) were all decided in
[`S-13`](../history/S-13-connect-and-discover-dispositions.md) and none has a record. What the
rebuild does today is one line in `ForestDiscovery`: each domain's controller is set to the domain's
own DNS name, so the run reads a domain from whichever machine DNS happens to return. There is no
selection, no site affinity, no capability check and no candidate list.

That last absence has consequences elsewhere.
[`0040`](0040-a-failed-domain-is-read-again-from-another-controller.md) requires a failed domain to
be read again *on the next controller listed for it*, and says the list is finite and its exhaustion
ends the run. Nothing produces such a list, so a retry resolves the same name and hopes for a
different machine - finding `F-S35-2`. And the predecessor refused to audit from a read-only domain
controller at two independent points; the rebuild cannot tell an RODC from a writable one at all -
finding `F-S35-3`.

The predecessor solved these with DNS SRV enumeration followed by an LDAP probe of every candidate,
reading `msDS-isRODC` from each. That works, and it is worth departing from deliberately rather than
by accident, because four things about it are weak:

- **Site is not authoritatively knowable from an SRV lookup.** A generic query carries no site, so
  the site affinity the ranking depends on rested on the least reliable input it had.
- **DNS is a cache of a claim.** Records are registered by controllers themselves; a decommissioned
  controller's records linger and a healthy one can fail to register.
- **It cost a connection per controller per domain** before a single object was captured, to learn
  something the forest already knows.
- **It was per-domain and fragile across the forest.** Disjoint namespaces or partial DNS breakage
  lose a child domain's candidates entirely, which is the same class of under-reading as `F-S28-1`.

## Decision

**The candidate list is read from the configuration partition.** Every controller in a forest holds
a complete replica of it, so one connection to the controller an operator named yields the physical
topology of the whole forest. `ForestPartitions` already relies on this property for cross-references
and for the same reason: **the forest's own account of itself, rather than one controller's.**

A subtree search for `nTDSDSA` objects beneath `CN=Sites` in the configuration naming context
returns, for every controller in the forest:

- `msDS-hasMasterNCs` - **the naming contexts it holds a writable replica of**, which *is* the
  per-domain candidate list `0040` assumes
- its site, from the great-grandparent container in the object's own distinguished name
- `dNSHostName`, from the `server` object above it, which is what a connection is opened to

**Discovery contacts nobody.** Sixty controllers are enumerated and ranked without a single
connection being opened. That is the whole gain over the predecessor: its cost model was N
connections before capture, and this one is one read.

**An RODC is excluded structurally rather than by probing.** A read-only controller does not list a
domain in `msDS-hasMasterNCs`; it lists it in `msDS-hasFullReplicaNCs`. Filtering on the first means
an RODC never enters a candidate list, so there is no capability check to forget to run and no
second refusal to keep in step with the first. This closes `F-S35-3` by construction rather than by
repeating the predecessor's two guards.

**Ranking is same-site first, then lexical.** The site of the machine running the audit is found by
matching its own addresses against the `subnet` objects in the same partition, taking the longest
prefix - which is what Netlogon does internally, computed here from data already read, and works
from a machine that is not joined to the forest being audited.

**A client that matches no subnet has no site preference, and the run says so.** Incomplete subnet
coverage is common. Falling back to lexical order is honest; resolving to a plausible-looking wrong
site is not, and *"this run had no site"* is the most useful thing a bundle can say when someone
asks why a capture took nine hours.

**Site-link costs are deliberately not used.** A shortest-path search over the inter-site transport
graph was considered and rejected. It pays off only in forests that actually costed their links,
degrades to hop-counting in the many that left every link at the default, and approximates an answer
the operator can simply type. **The manual override is the cheaper and more honest mechanism for
the case it would have served.**

**An operator may name the controller for a domain, and an ineligible name fails the run.** The
override is per-domain and per-run - never a stored setting, per
[`0047`](0047-settings-are-per-user-and-per-machine.md). If the named controller is not in the
candidate list for that domain, the run stops and says so. **It does not fall back to an automatic
choice.** The predecessor fell back silently, which meant an operator who mistyped a hostname got a
successful run against a different controller than the one they named, with nothing recording the
substitution. A pinned controller that was quietly not the pinned controller defeats the point of
pinning.

**DNS is used to bootstrap and to resolve, never to enumerate.** The first connection is made to
the forest the machine is already in, per
[`0053`](0053-the-tool-finds-its-own-forest.md), or to a name an operator gives when that is not
possible; and `dNSHostName` values are resolved to addresses. Nothing about *which* controllers
exist comes from DNS.

**— Corrected 2026-08-15. This record assumed a typed hostname while deciding something else.** As
written, the sentence above said the first connection is made to the name an operator gives, which
read as a requirement and was only ever an assumption carried in from the code of the day.
Automatic bootstrap is the sanctioned use this record already describes, not an exception to it.

**A domain with no candidates is a measured fact, and it stops for an attestation.** When the
configuration partition names no controller holding a domain's naming context, the forest itself is
saying so - an orphaned cross-reference, a failed demotion. It is a finding about the forest rather
than a fault of the run, **and the operator attests to the resulting exclusion before the run
proceeds**, per [`0054`](0054-a-domain-with-no-candidates-is-an-attested-exclusion.md). This is
categorically different from *controllers were named and none answered*, and the predecessor could
not tell the two apart because an empty SRV result looks identical to an unreachable one.

**— Corrected 2026-08-15. This record originally had the run record it and continue.** That would
seal a bundle missing an entire domain with no human statement attached to the gap, which is the one
thing every other route out of a run avoids. The finding is still recorded; it is no longer the only
thing recorded.

## Consequences

`0040` becomes implementable. The candidate list it assumes now exists, is ordered, and is finite.

Preflight has something to record. Which controllers were candidates, which was pinned, and whether
the pin came from ranking or from an operator, are all facts that exist before a connection is made
- which is what [`0048`](0048-preflight-proves-a-controller-before-a-run-commits.md) writes down.

Discovery now depends on reading `CN=Sites` in the configuration partition. It is readable by
authenticated users by default and is a small search even in a very large forest, but it is a new
read the product must be able to perform, and a failure to perform it is a failure to plan the run
at all.

**The list describes controllers that are registered, not controllers that are running.** A
decommissioned controller whose metadata was never cleaned up appears in it. That is not a defect
to be corrected here: it is precisely why preflight exists as a separate act, and why liveness is
never a discovery concern.

Nothing may restate this record. Rows, comments and notes cite `0050`.
