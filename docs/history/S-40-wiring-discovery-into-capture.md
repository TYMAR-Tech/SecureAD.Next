# S-40 - Wiring discovery into capture

> **This records session S-40 as of 2026-08-11. Nothing here states current behaviour.**  
> It is kept for the reasoning it carries, not as documentation. See [`docs/history/README.md`](README.md).

**Status: complete.** The re-pin `0055` requires is enforced by a test that fails when it is removed.

This document is discussion, not authority. Where it disagrees with the code, the code wins, and the
disagreement is a finding.

**Governing records:** [`0040`](../decisions/0040-a-failed-domain-is-read-again-from-another-controller.md),
[`0047`](../decisions/0047-settings-are-per-user-and-per-machine.md),
[`0048`](../decisions/0048-preflight-proves-a-controller-before-a-run-commits.md),
[`0050`](../decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md),
[`0053`](../decisions/0053-the-tool-finds-its-own-forest.md),
[`0054`](../decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md),
[`0055`](../decisions/0055-the-pdc-emulator-is-established-at-preflight.md).

---

## What this replaces

`S-39` built discovery and selection and wired none of it in. Two lines carried the old behaviour:
`ForestDiscovery` set each domain's controller to the domain's own DNS name, and `CaptureSession`
took a host name from a command line. Both are gone, replaced rather than wrapped.

---

## What was built

### The plan carries its own reasoning - `ForestPlan`

`CapturePlan` holds one controller per domain and nothing about why. That was enough while there was
no choice being made. It is not enough for `0040`, which needs the ranked alternatives when a read
fails, or for `0055`, which needs the topology and roles again at preflight. `ForestPlan` carries the
capture plan alongside the topology, the roles and the selection.

`ForestDiscovery.PlanAsync` now returns one. On the bootstrap connection it reads the candidate list
and the two forest-level roles, computes the operator's site, and ranks - all from the connection
already open, so `0050`'s claim that discovery contacts nobody is kept intact.

### Entry is a click, not a host name - `CaptureSession`

`ForestBootstrap.Enter` is the ordinary route: the machine's own domain first, a typed name only when
that fails. The order is `0053` and is held by a test in both directions. A typed name is **not**
tried when the machine found its own forest, even if one was supplied - quietly auditing a different
forest because a stale name sat in a field is not a thing this may do.

The bootstrap connection is closed as soon as discovery has finished with it and is never pinned.

`Enter` lives on `ForestBootstrap` rather than on `CaptureSession` because the session builds its own
channel factory per `0039` and a rule written inside it could not be exercised without a live forest.
That is the same reasoning `Preflight` already records for taking its factory as an argument.

### The re-pin - the point of the session

Preflight already opens a connection to each domain's chosen controller. Over that same connection it
now calls `ForestRoles.EstablishPdcEmulatorAsync`: one extra base request, no connection of its own,
which is the whole economic argument of `0055`.

Where the pinned controller turns out to be that domain's PDC emulator and re-ranking with that fact
produces a different controller, selection moves and **the domain is preflighted again** against the
new one. Where the site offers no alternative, the run proceeds and `ReadFromPdcEmulator` says so.

**The capture unit is rewritten, not just the report.** A re-pin that changed only what was displayed
would leave the run reading the machine the re-pin exists to avoid while every screen and file
claimed otherwise.

It is asked once per domain and never loops: re-ranking with the emulator known cannot return that
same emulator, so a second pass could only repeat the first.

**An overridden domain keeps its override through a re-pin.** An operator who named a controller gets
that controller or a refusal, per `0047`. Moving him off it because it holds a role would be exactly
the silent substitution the refusal exists to prevent.

### `IsComplete`, consumed rather than carried

`DomainSelection.IsComplete` reaches `DomainPreflight.SelectionWasInformed`, and
`PreflightReport.ChosenWithoutFullKnowledge` collects the domains it is false for. The CLI prints why
in words - no site of this machine's own, or a PDC emulator that could not be read. Neither blocks.
What it stops is a pinned host name reading as a fully informed choice, when an informed choice and a
coin toss between equals produce exactly the same one name.

### The override - refused, never softened

`--controller contoso.com=DC01.contoso.com`, repeatable, per run, never stored. A malformed pair and
the same domain named twice are both refused rather than last-one-wins: an operator who repeats a
domain has contradicted himself, and choosing one for him means reading from a controller he also
asked the run not to use.

An operator names a domain the way he says it and selection keys by naming context, so discovery
translates - and refuses a name matching no domain, listing the ones the forest declares.
`ControllerSelection`'s existing refusal of an ineligible controller reaches the CLI as a failure
exit. Neither is softened into a warning on the way out.

### The preview - `PlanPreview`

Per domain: the pinned controller, whether an operator named it, whether it is in this machine's
site, the **full ranked failover list**, and a note where the choice was made on incomplete
knowledge. Domains with no candidates are named with the reason. A topology short of controllers with
no host name is flagged, so a shorter candidate list cannot be read as a smaller forest.

It is a type in `SecureAD.Audit` rather than printing code in the CLI. The wizard's domain table and
a terminal show the same facts, and written twice they would drift - the first sign of it being a
preview that disagreed with the run it previewed.

---

## Proven

`DiscoveryWiringTests` (11). Whole of `SecureAD.Next.Tests`: **1093 passed, 0 failed**, up from 1082.

Mutations tried, each observed failing and then reverted and re-run green:

| Mutation | What failed |
|---|---|
| Re-pin disabled - `MoveOffPdcEmulator` always returns null | `ADomainIsMovedOffItsPdcEmulatorOncePreflightEstablishesIt`, `TheRepinnedControllerIsTheOneTheRunWouldRead` |
| Unknown-domain override softened from a refusal to a silent drop | `AnOverrideNamingADomainThisForestDoesNotHaveStopsTheRun` |
| Entry order swapped so a typed name is tried first | `AMachineInAForestEntersByItsOwnDomainAndNeverTheTypedName` |
| Failover list reversed | `TheFailoverListIsRankedAndShownInThatOrder` |

---

## Not built

**`0040`'s retry.** `DomainSelection.Failover` is produced in ranked order, carried through the plan
and printed by the preview - and **nothing walks it**. A domain whose read fails is not read again
from the next controller. This is `F-S40-1`.

**`0054`'s attestation.** A domain the forest names no controller for cannot yet be excluded under an
operator's statement, because the attestation surface is session 5. This is `F-S40-2`.

**`preflight.json` still carries no candidate list.** `0048` asks for it per domain along with
whether the pin came from ranking or an override. Both facts now exist. This is `F-S40-3`.

---

## Findings

**F-S40-1 - `0040` is Accepted and nothing enforces it.** The failover list is produced, ranked,
carried and displayed; no code path reads it when a domain fails. A run that loses a controller
mid-capture still loses the domain. **Contained:** the ordering is correct and tested, so the retry
has something to consume when it is written. **Severity:** medium - it is a stated resilience
guarantee the product does not have. **Status:** open, no decision. Session 3 is the natural home,
alongside the fan-out work.

**F-S40-2 - `0054` is Accepted and this session could not honour it.** A domain with no candidate
controllers must be excluded under an operator's attestation; the attestation surface is session 5.
**Decision:** until it exists, a capture **stops** rather than sealing a bundle silently missing a
domain, and `--validate` and `--preview` still report it. That is the one placeholder that cannot
produce the outcome `0054` exists to prevent. The refusal names the counts and points at `--preview`.
**Status:** placeholder in place, superseded by session 5.

**F-S40-3 - `S-37` described a `preflight.json` gap as a design choice, and it has outlived its
reason.** The passage said candidate lists and pin origin were absent because "today every domain has
exactly one controller, reached through its DNS name". That is no longer true of the code. The
document was corrected in place rather than deleted, because the reasoning it records is still why
the fields were not written at the time. **Status:** document corrected; the fields are still not
written, which is now a gap rather than a choice.

**F-S40-4 - `ForestRoles.With` silently did nothing for a domain it did not know.** It returned an
unchanged copy when the naming context matched no entry, so a re-pin against a mistyped domain would
have been indistinguishable from one that worked. Found by colliding with it while adding a duplicate
of the same method. A guard was added: it now throws. Nothing in production could reach the case -
`ForestRoles` is read for every forest domain and preflight iterates a subset - which is precisely
why it would have gone unnoticed. **Status: fixed.**

**F-S40-5 - filtering no-candidate domains would have made `CapturePlan.IsComplete` lie.**
`CapturePlan.For` derives `DeclaredDomains` from the same list it builds units from, so dropping a
domain before calling it shrinks both counts together and the completeness check stays true for a
plan missing an entire domain - `F-S28-1`'s exact failure, reappearing through the property meant to
catch it. The full declaration is now restored after the call. The comment at `CapturePlan.cs` line
79 predicted this would "break silently the day a configuration file pins real controllers".
**Status: fixed.**

**F-S40-6 - the shared controller fixture describes a forest that cannot exist.**
`ControllerModel`'s default has no `CN=Sites`, no schema head and no `CN=Partitions`, so a forest
built from it has no controllers at all. Harmless while nothing read them; not harmless now. Seeded
by an opt-in `TestForest` helper rather than in `ControllerModel` itself, because adding objects to
the default changes the object sets the end-to-end tests assert on. **Contained:** every test that
needs them asks for them. **Severity:** low, but it is `F-S39-4` for the third time and the next
component to read a universal object will hit it again. **Status:** open, no decision.

**F-S40-7 - `F-S39-1` was accurate and the brief's description of it was not.** The brief said the
finding claimed two build-failing guards were missing and that the real defect was stale prose in
`sessions/README.md`. The finding already said that. What it needed was a decision line, which it now
has, plus one correction: there were **three** stale claims in `sessions/README.md`, not one - the
four-heading enforcement, the `SessionCompletionTests` table, and a sentence asserting the rebuild
still carried a `SessionPromptTests` of its own. The old tree's `SessionPromptTests` does exist and
governs `docs/review/README.md` alone; the rebuild's was deleted deliberately on 2026-08-14.
**Status: fixed** - prose corrected, no test reinstated.

**F-S40-8 - the preview told a live forest that its controllers were somewhere else, having never
established where "here" was.** Found on the first run against a real directory. `ad.lab` matched no
subnet, so `OperatorSite` was null; `DomainSelection.IsInOperatorSite` is false in that case as well
as when a controller genuinely is elsewhere - its own doc comment says so - and the preview rendered
that single false as *"(another site)"* for all three domains. A statement about where a customer's
controllers sit relative to a place the product never located, which
[`0002`](../decisions/0002-absent-view-means-degraded-run.md) forbids and which is `F-S35-1`'s exact
shape. Three renderings now, not two: same site, another site, and the site the forest names with
this machine's own position stated as unknown. **Severity:** would have misled an operator about his
own topology. **Status: fixed**, held by
`AMachineWithNoSiteIsNotToldWhichControllersAreElsewhere`, mutation-proven.

**F-S40-9 - "matched no subnet" covered two faults with different remedies.** A forest declaring no
subnets at all and a forest declaring subnets none of which contain this machine's address read
identically. The first is fixed by defining subnets, the second by finding out why this machine is
outside all of them. Now distinguished, and the count is stated. **Status: fixed.**

**F-S40-10 - the same defect one message along, found by the first live `--validate`.** Two lines
asserted site-relative facts on a run that had no site. *"No other controller for it was found in
this site"* implied both that a site filter had been applied and that other controllers existed
somewhere - against three domains the forest names exactly one controller for each. And the
"chosen without every input" line still said *"matched no subnet the forest declares"* after
`F-S40-9` had established that this forest declares none. `DomainPreflight` now carries
`OtherControllersInTheForest`, so "there was nowhere else to go" and "somewhere else existed and was
not preferred" are told apart, and the site reason defers to `--preview` rather than restating a
claim it cannot support. **Status: fixed.** Recorded separately from `F-S40-8` because it is
evidence the first fix was applied to the symptom rather than searched for across the surface -
the second instance was written by the same hand on the same day and survived.

**F-S40-11 - a capture read three domains from their PDC emulators and told nobody.** The warnings
`0055` requires were printed on the `--validate` path only. A real run printed `Sealed:` and nothing
else, and `preflight.json` - the file that stays with the bundle - carried none of the PDC or
selection fields either. So the run proceeded exactly as `0055` allows and the "and says so" half
happened nowhere: not on the console, not in the evidence. Found on the first full capture against a
live forest. The warnings are now shared by both paths and emitted **before** reading starts rather
than beside `Sealed`, because a warning an operator gets after the fact is about a choice he can no
longer change. **Status: fixed**, held by
`ThePreflightFileRecordsThatADomainWasReadFromItsPdcEmulator`.

**F-S40-12 - `0048`'s two owed fields are now written, and `F-S40-3` is closed.** `preflight.json`
carries the ranked candidate list and whether the pin came from ranking or an operator, alongside the
`0055` facts. The `PreflightFile` remarks claiming *"today every domain has exactly one controller,
reached through its DNS name"* - the same stale sentence corrected in `S-37` as `F-S40-3`, in a
second place nobody looked - is gone. **Status: fixed.**

**Three instances of one mistake.** `F-S40-8`, `F-S40-10` and `F-S40-11` are the same failure:
something true was established in one place and not carried to every place a reader looks. Each was
found by running the product rather than by reading it, and each was fixed where it was reported
rather than searched for across the surface - which is why there were three. The remaining risk is
that a fourth exists somewhere nothing has printed yet.

**F-S40-13 - `preflight.json` called an uninformed choice complete.** On the live bundle,
`"IsComplete": true` sat two lines below `"SelectionWasInformed": false`. Both were true and they
measure different things - all four questions were put, and the controller was chosen without
knowing where the run was - but a reader who was not present takes a field called *complete* reading
*true* as an all-clear. **Decision:** the file's contract is renamed to say what it measures:
`AllQuestionsWereAsked` per domain and `AllDomainsWereAsked` for the file. In-memory types keep
`IsComplete`, which is this codebase's convention across `ForestTopology`, `ControllerSelection`,
`CapturePlan` and others; only the contract with an outside reader changed, and it changed while
nothing consumed it. **Status: fixed.**

Renaming those two members removed the shape gate 4 recognises, and the gate caught it - which is
worth recording, because a gate that had let a newly unvouched type through would have been the
gate-that-measures-nothing shape in the one check built to prevent it. `*WereAsked` was added to
`VouchShapes` on the same footing `*AreComplete` was: it is a statement of whether the question was
put, which is exactly what the gate asks for. The widening was mutation-tested - both names altered
so they no longer match, gate fires; matcher is anchored, so `AllQuestionsWereAskedX` is correctly
refused.

---

## What the specification got wrong

`S-38` § 7 lists this session as "wire it into capture", which reads as plumbing. Two of its items
were not: the re-pin is a behaviour `S-39` deliberately left unbuilt and named as unenforced, and the
`0054` placeholder is a product decision about what a run does when it cannot audit a domain.

`S-38` § 9's note that `git grep` does not see untracked files was written for exactly the mistake
this session opened with: every search for `S-39`'s output returned nothing, and the conclusion drawn
was that session 1 had not run. It had. The note is right and was not read early enough.

---

## Owed

- `0040`'s retry (`F-S40-1`), naturally session 3.
- `0054`'s attestation (`F-S40-2`), session 5.
- The `preflight.json` fields `0048` asks for (`F-S40-3`).
- A shared fixture that looks like a forest (`F-S40-6`).
