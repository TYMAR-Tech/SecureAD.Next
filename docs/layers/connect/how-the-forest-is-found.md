# How the forest is found

**Layer.** How a run finds the forest it is in, learns what that forest contains, and decides which
domain controller each domain will be read from — all before anything is captured.

The code is [`ForestBootstrap`](../../../next/src/SecureAD.Audit/Connect/ForestBootstrap.cs),
[`MachineDomain`](../../../next/src/SecureAD.Audit/Connect/MachineDomain.cs),
[`MachineAddresses`](../../../next/src/SecureAD.Audit/Connect/MachineAddresses.cs),
[`ForestDiscovery`](../../../next/src/SecureAD.Audit/Connect/ForestDiscovery.cs),
[`ForestPartitions`](../../../next/src/SecureAD.Audit/Connect/ForestPartitions.cs),
[`ForestTopology`](../../../next/src/SecureAD.Audit/Connect/ForestTopology.cs),
[`ForestRoles`](../../../next/src/SecureAD.Audit/Connect/ForestRoles.cs),
[`OperatorSite`](../../../next/src/SecureAD.Audit/Connect/OperatorSite.cs),
[`ControllerSelection`](../../../next/src/SecureAD.Audit/Connect/ControllerSelection.cs),
[`ForestPlan`](../../../next/src/SecureAD.Audit/Connect/ForestPlan.cs) and
[`PlanPreview`](../../../next/src/SecureAD.Audit/Connect/PlanPreview.cs).

Governed by [`0053`](../../decisions/0053-the-tool-finds-its-own-forest.md),
[`0050`](../../decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md),
[`0052`](../../decisions/0052-the-domain-is-the-only-unit-of-scope.md),
[`0054`](../../decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md) and
[`0055`](../../decisions/0055-the-pdc-emulator-is-established-at-preflight.md).

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `IMachineDomain` | What the machine running the audit knows about its own domain membership. The whole platform dependency, kept to two properties |
| `MachineDomain` | The real implementation of that, reading the machine's DNS suffix and NetBIOS domain |
| `MachineAddresses` | The addresses this machine holds, which is how its site is worked out |
| `ForestEntry` | The first connection of a run, and where the name it was made to came from |
| `ForestEntrySource` | Which of the three routes in supplied that name — DNS suffix, NetBIOS name, or a name the operator typed |
| `ForestBootstrap` | Makes that first connection, to a domain name rather than a host |
| `ForestDiscovery` | Reads what the forest contains over that one connection, and contacts nobody else |
| `ForestController` | One controller the forest declares, with the site it sits in and the replicas it holds |
| `ForestSubnet` | One address range the forest associates with a site |
| `ForestTopology` | Every controller, every site and every declared address range, read from the configuration partition |
| `ForestRoles` | Which controllers hold operations master roles, as far as the forest was willing to say |
| `RoleHolder` | One such role and the controller holding it, or the fact that it could not be established |
| `PdcEmulatorKnowledge` | Whether a domain's PDC emulator is established, not yet established, or could not be read — three states and not two |
| `DomainPdcEmulator` | One domain's PDC emulator, and how firmly that is known |
| `OperatorSite` | Which site the machine running the audit is in, computed from the forest's own subnets |
| `ControllerSelection` | Ranks the candidates and pins one controller per domain. Pure arithmetic over data already read |
| `DomainSelection` | Why a controller was chosen to read a domain from, in the order the reasons were applied |
| `ForestPlan` | What a run would read: one entry per domain, and the domains it cannot |
| `PlanPreview` | Works that plan out when the window opens, rather than on a press |

<!-- TYPES:END -->

This table is the page's claim of ownership, and it is bound in both directions against the public
types the files above declare: one they declare and this table omits fails the build, and so does a
row naming something they do not. `ForestPartitions.cs` is named in the header and contributes no
row, because the types it works with are declared elsewhere in the component.

**Nineteen types, one component, and the reason they are one.** This page describes a single
sequence — find the forest, read what it contains, decide which controller each domain is read
from — and every type above is a step in it or a result of one. Splitting the sequence across pages
would put the ranking rules on one page and the data they rank on another.

---

## The way in

> **The first connection is made to a domain name, not to a host.**

That indirection is the whole mechanism. A domain name is something the machine already knows; a
host name is not. The Windows domain controller locator turns the one into a nearby live controller.
This is the sanctioned use of DNS that `0050` describes — **bootstrapping, never enumerating.**
Nothing about *which* controllers exist comes from it.

The order is DNS suffix, then NetBIOS name, then a typed name — and it is not an implementation
detail:

| Source | When |
|---|---|
| `MachineDnsDomain` | The ordinary route in |
| `MachineNetBiosDomain` | The machine has no DNS suffix |
| `TypedName` | Recovery only — not domain-joined, or auditing someone else's forest |

**A typed name is the weakest input available** and so is the recovery path rather than the ordinary
route. It is the one thing in the whole plan that nothing verifies before use, it names a machine
rather than a directory, and mistyping it is indistinguishable from naming a controller that is
down. Trying it first would make the recovery path the normal one, and would report a typing mistake
as though the forest were unreachable.

**A typed name is not tried when the ordinary route succeeded**, even if the operator supplied one.
Quietly auditing a different forest because a stale name was left in a field is not a thing this may
do.

**The controller this lands on is never pinned.** It answers *what forest is this* and nothing else.
A run that treated it as the controller to capture from would be reading a whole forest from
whichever machine the locator happened to return — the behaviour `0050` exists to replace.

### What the machine knows about itself

`MachineDomain` is the whole platform dependency, kept to two properties so everything that decides
where a run starts can be exercised without being run on a domain-joined machine.

**Neither value is inferred from the other.** A machine can have a NetBIOS domain and no DNS suffix,
and in a disjoint namespace the NetBIOS name is not the first label of the DNS name. Deriving one
from the other would produce a plausible-looking domain name that resolves to nothing, and the run
would report that a forest could not be reached when what actually happened is that this product
invented its name.

`USERDOMAIN` is compared against the computer name, because on a workgroup machine it is the
machine's own name — and returning that would send the locator looking for a forest that does not
exist.

---

## What the forest contains

**Discovery contacts nobody beyond the bootstrap connection.** Every controller in a forest holds a
complete replica of the configuration partition, so one connection yields the topology of the whole
forest. The predecessor's cost model was a DNS enumeration and then a connection to every candidate
before a single object was captured. This is one read.

### Which naming contexts are domains is the forest's answer, not one controller's

> This is `F-S28-1`, and it is the most expensive mistake this layer has made.

An earlier version treated every published naming context that was not the configuration or schema
partition as a domain. That was wrong twice over. It **over-read**, because an application partition
is spelled exactly as a domain is — `DC=DomainDnsZones,DC=example,DC=com`. Far worse, it
**under-read**: an ordinary domain controller publishes only the partitions it holds, so in a forest
of nine domains the answer named one, and **the run sealed a bundle covering a ninth of a forest
with nothing saying so.**

`ForestPartitions` reads the cross-references in the configuration partition instead, which every
controller in the forest holds and which name every partition the forest has.

**The classification rule is Microsoft's and it is quoted rather than remembered.** A cross-reference
representing a domain has both `ADS_SYSTEMFLAG_CR_NTDS_NC` (`0x1`) and
`ADS_SYSTEMFLAG_CR_NTDS_DOMAIN` (`0x2`) set in `systemFlags`; an application directory partition has
`NTDS_NC` set and `NTDS_DOMAIN` clear, and so do the configuration and schema cross-references
([Enumerating Application Directory Partitions in a
Forest](https://learn.microsoft.com/windows/win32/ad/enumerating-application-directory-partitions-in-a-forest)).
**Both bits are required** — testing only the domain bit would test a bit whose meaning is defined
for cross-references held in the directory, on one that may not be.

**Anything that is not a domain is recorded rather than dropped.** A partition this run will not
read is a coverage entry per `0052`, and silence about it is the one thing an audit tool cannot
produce.

**A cross-reference with no `nCName` refers to an external directory** and is skipped — there is
nothing there for a capture to read.

### The forest is named by its root domain

`rootDomainNamingContext` comes from the RootDSE, not from the shape of the shortest name in the
list. If the RootDSE names a root domain the cross-references do not declare, the run stops: the two
disagree about what this forest is, and **a bundle named for the wrong forest would be offered as a
comparison partner for a forest it is not evidence of.**

### The candidate list

`ForestTopology` reads every controller, every site and every declared address range from the
configuration partition.

**Eligibility is holding a writable replica.** `msDS-hasMasterNCs` is the whole of the test — a
read-only controller declares its replicas in `msDS-hasFullReplicaNCs` and never reaches the
candidate list, so nothing downstream has to know what one is.

**A site is read from where an object sits, not from an attribute.** An `nTDSDSA` object is named
`CN=NTDS Settings,CN=<server>,CN=Servers,CN=<site>,CN=Sites,…`, so the site is the
great-grandparent container's name. There is no attribute stating it. **That makes the depth
load-bearing**: counting wrong yields a plausible-looking wrong site rather than an error, which
would rank a distant controller first and cost hours of a capture with nothing reporting why.

**The two object classes are told apart by what they carry**, not by re-reading their object class:
only an `nTDSDSA` declares `msDS-hasMasterNCs`, and only a `server` declares `dNSHostName`.

**A controller that cannot be named is recorded, never dropped.** An `nTDSDSA` whose `server` parent
carries no `dNSHostName` is one this product cannot connect to. Silently omitting it would shorten a
candidate list with nothing saying so, and per
[`0002`](../../decisions/0002-absent-view-means-degraded-run.md) an absence the product created may not
be presented as a fact about the forest.

**`DirectoryServiceDn` is carried because a role is recorded under it and nothing else.** An
operations master role is an `fSMORoleOwner` attribute whose value is the holder's `nTDSDSA`
distinguished name — never a host name.

---

## Which controller each domain is read from

`ControllerSelection` is **pure arithmetic over data already read.** It opens no connection and
resolves no name, which is what lets every ranking rule be exercised without a directory.

**The order of the rules is the whole of the behaviour:**

1. **Same site first.** A wide-area read of a large domain is the difference between an audit that
   finishes in an evening and one that does not.
2. **Then no established operations master role.**
3. **Then lexically by host name**, so the same candidate set always produces the same choice and
   two runs a week apart pick the same controller unless the forest changed.

### Why the PDC emulator is ranked last

It carries time synchronisation, password change chaining, account lockout evaluation and Group
Policy editing for the whole domain, and a forest-wide audit is a read measured in hours. **Pointing
one at the PDC emulator is the single clearly bad choice available to selection**, and it is the
choice a ranker makes by accident when it cannot tell which machine that is.

**Two roles are free and the rest are not.** The schema master and the domain naming master are
recorded in the schema and configuration partitions, which every controller holds — so both are
answered by the connection discovery already has open. A domain's PDC emulator is recorded on that
domain's own naming context head, which a controller of a different domain does not hold, and
referral chasing is off. So the PDC emulator is established at **preflight**, over a connection that
already exists (`0055`), and discovery leaves every domain at `NotYetEstablished`.

**`NotYetEstablished` is not `holds no role`, and that is what the enumeration exists for.** A domain
whose PDC emulator has not been established has every controller looking, to a ranker, exactly like
one holding no role — so the busiest machine sorts equal with the quietest and may well be pinned.
Collapsing the two states would let the run read a whole domain from its PDC emulator with nothing
recording that it had. `CouldNotBeRead` is the third state: the domain is still audited, and what is
lost is recorded rather than absorbed.

### An override is obeyed or the run stops

A named controller that is not an eligible candidate **fails the whole selection and never falls back
to the automatic choice.** The predecessor fell back silently, so an operator who mistyped a host
name got a successful run against a controller they did not name, with nothing recording the
substitution. **A pinned controller that was quietly not the pinned controller defeats the point of
pinning.** An override naming a domain this forest does not have is refused the same way.

### A domain with no candidates is not an error here

The forest itself is saying no controller holds it — an orphaned cross-reference, a failed
demotion. What happens next is an operator's attestation per `0054`. Selection records the fact and
leaves the decision to the surface that can ask a human. The domain gets no entry in the plan and is
carried in `DomainsWithNoCandidates` instead.

### `IsComplete` is why a host name is not enough

A caller reading only `PinnedController` cannot tell a fully informed choice from a coin toss
between equals, **because both produce exactly one host name.** `IsComplete` is false where the run
has no site of its own, or where the domain's PDC emulator was not established.

---

## Which site the operator is in

`OperatorSite` computes this from the forest's own subnets rather than asking Windows, so it works
from a machine that is not joined to the forest being audited. This is what Netlogon does internally.

**The longest prefix wins, and that is not a tie-break.** A forest routinely declares `10.0.0.0/8`
for a whole region and `10.20.30.0/24` for one office inside it. Both contain the same machine and
only the second is true about where it is. Taking the first match, or the shortest, would put a
controller on another continent at the top of the list. Equal lengths resolve to the first the
forest returned, which keeps the answer stable across runs.

**A machine matching nothing has no site, and that is a value.** Incomplete subnet coverage is
common. *This run had no site* is the most useful thing a bundle can say when somebody asks why a
capture took nine hours.

**A malformed subnet name is skipped rather than failing the run.** The name of a subnet object *is*
the range, so a name that is not a range is a subnet nobody can route by — the forest's defect, not
this run's. Refusing to plan a capture over it would let one bad object stop an audit with nothing
else wrong with it. Ranges of the wrong address family are skipped for the same reason.

**Loopback, link-local and tunnel addresses are excluded** from the machine's own addresses. None
appears in a forest's subnet objects, and a machine matched on one would be sited by an accident of
its own network configuration rather than by where it is. `MachineAddresses` returns a `Result`
rather than a bare list, because an empty list and a failed enumeration are different facts with the
same shape.

---

## The preview

`PlanPreview` is a type rather than printing code because the same four facts per domain are what
the New Audit wizard's table shows and what an operator checking a scheduled run needs on a
terminal. Written twice they would drift, and the first sign would be **a preview that disagreed with
the run it was previewing.**

**It contacts nobody, and its limit is stated rather than hidden**: a domain's PDC emulator is not
established until preflight, so a preview cannot promise the run will not land on one. It says which
domains are chosen on incomplete knowledge instead of implying none are.

**Three answers about site, not two.** `IsInOperatorSite` is false both when the controller is
genuinely elsewhere and when the run has no site of its own. Saying *"another site"* for a run that
never established its own site is a statement about where a customer's controllers are that the
product did not measure. Likewise a forest that declares no subnets at all and a machine matching
none of the subnets it does declare are different faults with different remedies.

---

## What is built

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| see every domain of the forest without naming anything | `ForestDiscoveryTests` | |
| see, per domain, which controller would be read | `ControllerSelectionTests.AControllerInTheOperatorSiteIsPinnedOverALexicallyEarlierOne` | |
| see that a controller in his own site is preferred over one holding a role | `ControllerSelectionTests.SiteOutranksHoldingARole` | |
| see the failover order, and not just the winner | `ControllerSelectionTests.TheFailoverListIsTheRestOfTheRankingInOrder` | |
| be told the choice was made without every input, rather than shown a confident answer | `ControllerSelectionTests.ADomainRankedWithoutItsPdcEmulatorIsNotComplete` | |
| name a different controller, and have it obeyed | `ControllerSelectionTests.AnOverrideIsObeyedAndTheRestRemainAsFailover` | |
| be refused, in the audit layer's own words, when that name is not a candidate | `ControllerSelectionTests.AnOverrideThatIsNotACandidateStopsTheRun` | |
| be certain a refused override never silently falls back to the automatic choice | `ControllerSelectionTests.AnOverrideThatIsNotACandidateNeverFallsBack` | |
| learn that a domain has no readable controller, instead of it vanishing from the run | `ControllerSelectionTests.ADomainWithNoCandidatesIsRecordedRatherThanPlannedAgainst` | |
| be told plainly that this machine's site is unknown, when the forest declares no subnets | `OperatorSiteTests.AForestDeclaringNoRangesLeavesTheRunWithNoSite` | |
| see a domain with no candidates shown rather than omitted | `DiscoveryWiringTests.ADomainWithNoCandidatesIsShownRatherThanOmitted` |  |
| see the failover list ranked, and shown in that order | `DiscoveryWiringTests.TheFailoverListIsRankedAndShownInThatOrder` |  |
| be certain an override naming an ineligible controller stops the run | `DiscoveryWiringTests.AnOverrideNamingAnIneligibleControllerStopsTheRun` |  |
| be certain an override naming a domain this forest does not have stops the run | `DiscoveryWiringTests.AnOverrideNamingADomainThisForestDoesNotHaveStopsTheRun` |  |
| tell a forest with no subnets from one whose subnets did not match | `DiscoveryWiringTests.AForestWithNoSubnetsIsDistinguishedFromOneWhoseSubnetsDidNotMatch` |  |
| be certain a choice made without every input is not called complete | `DiscoveryWiringTests.ThePreflightFileDoesNotCallAnUninformedChoiceComplete` |  |

**Verified in the lab.** 2026-08-21, against `ad.lab` with `ba.ad.lab` and `ph.ad.lab`, one
controller per domain, no subnets declared. Two things were checked by eye because no test can check
them: the PDC emulator prompt appeared on no row, and no domain was described as being in another
site.

---

## What this document cannot tell you

**Whether a name that does not resolve is told apart from a host that is switched off.** Both arrive
as the same protocol error, and separating them means resolving the name deliberately — a further act
against DNS that would need weighing against `0050`. Raised by the amendment to
[`0018`](../../decisions/0018-connection-security-is-an-ordered-ladder.md), not decided there.

**What an operator does when he wants to pin controllers permanently.** Referred to as *the
configuration file* in `A2` of the reference inventory, never designed. Hand-typing a list of
controllers now would put typos into the first real run.

**What a run does when the chosen controller fails part-way through.**
[`0040`](../../decisions/0040-a-failed-domain-is-read-again-from-another-controller.md) decided a failed
domain is read again from another controller, and the ranked failover list exists for it — but
**nothing walks that path today** (`F-S40-1`, on the punch list). Whether the operator is told, and
when, is undecided.
