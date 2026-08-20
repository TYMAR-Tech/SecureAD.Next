# S-39 - Discovery and controller selection

> **This records session S-39 as of 2026-08-11. Nothing here states current behaviour.**  
> It is kept for the reasoning it carries, not as documentation. See [`docs/history/README.md`](README.md).

**Status: complete**, with one item deliberately deferred to session 2 - see § `Not built`.

This document is discussion, not authority. Where it disagrees with the code, the code wins, and the
disagreement is a finding.

**Governing records:** [`0050`](../decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md),
[`0053`](../decisions/0053-the-tool-finds-its-own-forest.md),
[`0054`](../decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md),
[`0055`](../decisions/0055-the-pdc-emulator-is-established-at-preflight.md).

---

## What this replaces

One line. `ForestDiscovery` set each domain's controller to the domain's own DNS name, so a domain
was read from whichever machine DNS happened to return. There was no candidate list, no site
affinity, no way to tell a read-only controller from a writable one, and nothing for
[`0040`](../decisions/0040-a-failed-domain-is-read-again-from-another-controller.md)'s failover to
walk. That line is still in place: nothing built here is wired into a run yet, which is session 2.

---

## What was built

### The candidate list - `ForestTopology`

A `CN=Sites` read of the configuration partition, which every controller in the forest holds a full
replica of, so one connection describes the whole forest. Per controller: the domains it holds a
**writable** replica of from `msDS-hasMasterNCs`, its site from the great-grandparent container of
its own distinguished name, and its `dNSHostName` from the `server` object above it.

A read-only controller lists its domains in `msDS-hasFullReplicaNCs` and so cannot enter the list at
all. That attribute is deliberately **not requested**, so no reader is invited to filter on it
instead - the refusal exists in one place and cannot be half-removed.

A controller the forest names but gives no host name for is carried in `ControllersWithNoHostName`,
and `IsComplete` says whether any exist. A candidate list one controller short, with nothing
recording why, is indistinguishable from a forest that really has one fewer controller.

### The operator's site - `OperatorSite`

Longest-prefix match of the machine's own addresses against the forest's `subnet` objects, which is
what Netlogon does internally, computed here from data already read and working from a machine not
joined to the forest being audited. A machine matching nothing has **no site**, carried as null.
Nothing guesses.

It is a separate component because it reads nothing. Keeping the arithmetic apart from the directory
access is what lets ranking be exercised without a directory.

### Operations master roles - `ForestRoles`

Added this session. A role is not an attribute of a controller: it is one `fSMORoleOwner` attribute
on the object the role governs, naming its holder by that controller's `nTDSDSA` distinguished name.
`ForestController` therefore gained `DirectoryServiceDn`, without which a role holder cannot be told
apart from any other candidate.

The **schema master** and **domain naming master** are read at discovery, free, on the connection
already open. Each domain's **PDC emulator** is not, and the reasoning is `0055` rather than repeated
here. Discovery leaves every domain at `PdcEmulatorKnowledge.NotYetEstablished`;
`EstablishPdcEmulatorAsync` is what preflight calls over a connection it already holds.

**Three states, not two.** `NotYetEstablished`, `Established`, `CouldNotBeRead`. A ranker that reads
an unasked question as a clean answer sorts the PDC emulator level with every other controller in
its domain and can pin an hours-long audit onto the machine handling that domain's password changes,
lockouts and time - with nothing recording that it had. `IsComplete` states whether every domain was
actually answered.

A holder the forest names but this run cannot match to a candidate is carried with the name the
forest gave and no host name, rather than dropped
([`0002`](../decisions/0002-absent-view-means-degraded-run.md)).

### Ranking and pinned selection - `ControllerSelection`

Pure arithmetic over what was already read. It opens no connection and resolves no name, so every
rule is exercised without a directory.

The order is the whole of the behaviour: **same site**, then **holds no established operations master
role**, then **lexically by host name**. The first survivor is pinned and the rest become that
domain's ordered failover list, which is what `0040` walks when a read fails. Lexical order last is
what makes two runs a week apart pick the same controller unless the forest changed.

An override is obeyed, or the run stops. A named controller that is not an eligible candidate for
that domain fails the whole selection, and the refusal names both what was asked for and what would
otherwise have been chosen - so the substitution that did not happen is visible in the words.

`DomainSelection.IsComplete` says whether the domain was ranked on every input the ranking wants.
It is false where the run has no site of its own, and false where the domain's PDC emulator was not
established - in which case the busiest machine in the domain sorted level with the rest and may be
the one pinned. A caller reading only the pinned host name cannot tell a fully informed choice from
a coin toss between equals, because both produce exactly one name.

A domain the forest names no writable controller for lands in `DomainsWithNoCandidates`. It is not
an error here: what happens next is an operator's attestation per `0054`.

### Entry - `ForestBootstrap`

The machine's own DNS domain suffix, falling back to its NetBIOS domain name, and the first
connection is opened **to that domain name rather than to a host**. That indirection is the whole
mechanism: a domain name is something the machine already knows, and a host name is not. A typed
name survives as the recovery path, for a machine that is not domain-joined or an operator auditing
a forest that is not his own.

A name that does not answer is **reported, not retried under the other form**. Falling through from
the DNS name to the NetBIOS name would report the second failure for the first attempt, and an
operator would be told the wrong thing about their own forest.

A machine with neither name is not in a forest and says so, having attempted no connection - there
is no name to attempt one to.

`IMachineDomain` is the whole of the platform dependency, two properties wide, so entry can be
exercised for a domain-joined machine, a workgroup machine and a machine with a NetBIOS name and no
DNS suffix without any of them being the machine the tests run on. `MachineDomain` reads the DNS
suffix from the network stack rather than an environment variable a profile can carry stale, and
treats a `USERDOMAIN` equal to the computer name as no domain at all - which is what a workgroup
machine reports.

**The bootstrap controller is never pinned.** It answers one question, and selection proceeds from
the configuration partition it yields.

---

## Proven

`ForestTopologyTests` (11), `OperatorSiteTests` (9), `ForestRolesTests` (10),
`ControllerSelectionTests` (13), `ForestBootstrapTests` (7). Whole of `SecureAD.Next.Tests`:
**1082 passed, 0 failed**, up from 1052 at the start of this session.

Mutations tried, each observed failing and then reverted and re-run green:

| Mutation | What failed |
|---|---|
| Site walk shortened by one container | site read `Servers` rather than the site name |
| Longest-prefix rule removed | a branch-office machine placed in the regional site |
| Failed PDC read returned as `Established` | `APdcReadThatFailsIsRecordedRatherThanTakenAsNoRole` |
| Discovery seeding domains as `Established` | three tests, including `AControllerInAnUnaskedDomainDoesNotReportAsHoldingNoRole` |
| Unmatched role holder dropped | `AnUnmatchedRoleHolderIsCarriedRatherThanDropped` |
| Role rank applied before site rank | `SiteOutranksHoldingARole` |
| Ineligible override falling back to the ranked choice | both override tests |
| NetBIOS name preferred to the DNS suffix | three bootstrap tests |
| A failed DNS-name entry retried as the NetBIOS name | `ADnsDomainThatDoesNotAnswerIsNotRetriedAsNetBios` |

---

## Not built

One item, and it belongs to session 2 because it needs preflight:

**The re-pin `0055` requires.** Where preflight proves the pinned controller is the domain's PDC
emulator, selection must choose a same-site alternative and preflight that domain again.

Until it exists, `ControllerSelection` can and will pin a PDC emulator whenever the run has not
established which controller that is - which, at the end of discovery, is every domain. It reports
that honestly through `IsComplete`, and nothing acts on the report. **A stated requirement with no
enforcement is worth naming rather than leaving implied**, and this one is the owner's: an audit is
not to be read from a PDC emulator where it can be avoided.

Nothing built here is wired into a run. `CaptureSession` still takes a host name and
`ForestDiscovery` still sets each domain's controller to the domain's own DNS name. That wiring is
session 2.

---

## Findings

**F-S39-1 - two documented build-failing guards over session prompts do not exist.**
[`sessions/README.md`](../next/sessions/README.md) stated that the four required sections of a prompt are
*"Enforced by `SessionPromptTests`, which fails the build rather than leaving it to a reader"*, and
that `SessionCompletionTests` holds its unrun-prompt table in both directions. `SessionPromptTests`
exists but governs the `## Session prompt` section of `docs/review/README.md` only, and
`SessionCompletionTests` does not exist anywhere - `git ls-files "*SessionCompletion*"` returns
nothing. No prompt in `docs/next/sessions/` has ever been machine-checked. This is the
gate-that-measures-nothing shape, found in paperwork rather than in product code. **Contained:**
prompts follow the documented shape by hand. **Severity:** low.

**Decision:** the prose is corrected and no test is reinstated. The rebuild's own
`SessionPromptTests` was deleted deliberately on 2026-08-14 for the reason
[`README.md`](../next/README.md) records - it could not be broken by any change to the product, and what it
could not check was whether the scope was the right scope. Reinstating it would recreate a guard
that always says yes. `sessions/README.md` now states plainly that the shape is held by a reader.
**Status: fixed at `S-40`** - three claims were stale rather than one: the four-heading enforcement,
the `SessionCompletionTests` table, and a sentence asserting the rebuild still carried a
`SessionPromptTests` of its own.

**F-S39-2 - the FSMO criterion of `0050` reads as uniformly exact and cannot be.** `0050` ranks on
"holds no FSMO role" alongside "same site", both as facts available from one read. The forest roles
are; a domain's PDC emulator is not, because it sits on a naming context head the bootstrap
controller does not hold. **Status: decided** - `0055`, which states when each input becomes
available and leaves `0050` unamended.

**F-S39-3 - gate 4 caught a bare collection during this session, and the catch was correct.**
`ForestRoles.PdcEmulators` initially returned `IReadOnlyList` from a type carrying no vouch, so a
caller could not distinguish a forest that answered every PDC question from one that answered none -
both are a full list of domains. `IsComplete` was added. Recorded because it is evidence the gate
measures something, against the standing worry about guards that always say yes. **Status: fixed.**

**F-S39-4 - the test harness lacked objects every real forest has.** `ControllerModel` had no schema
head and no `CN=Partitions`, so the first run of `ForestRolesTests` failed eight of ten. The
component was right to refuse a base read that returned nothing; the fixture was wrong. Noted because
a fixture missing a universal object is a way for a future test to pass against a forest shape that
cannot exist. **Status: fixed.**

**F-S39-5 - two ranking tests were written that would have passed while measuring nothing.**
`AnEstablishedRoleHolderIsRankedBelowAControllerHoldingNoRole` and `SiteOutranksHoldingARole` named a
PDC emulator but never established it, so the role stayed `NotYetEstablished`, the role rank never
fired, and the expected controller won on lexical order instead. One of the two passed in that
state. Caught only because the other failed, and both were corrected to establish the role before
asserting on it. Recorded because it is the exact shape this repository has been bitten by twice: a
green check sitting downstream of a rule that was never exercised. **Status: fixed.**

---

## What the specification got wrong

`S-38` § "Choosing a controller per domain" says the PDC emulator *"costs one base read per domain"*.
It costs one base read per domain **plus a connection per domain**, because a controller does not
hold another domain's naming context head and referral chasing is off. The prompt anticipated exactly
this and pre-authorised recording it rather than quietly dropping the rank; `0055` is the result.
