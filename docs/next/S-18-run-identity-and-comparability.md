# S-18 — Run identity and comparability

**Type:** slice
**Inventory rows:** F1, F2, F3, F6, F9, F10, F17
**Date:** 2026-08-12

## What it does

This is the part of the product that knows **which audit is which**, **what became of it**, and
**whether it may be used**. Nothing here reads a directory or writes evidence. It answers three
questions that everything downstream depends on:

- *Which forest was this?* — `ProfileId`, so a forest's audits stay together as a history.
- *What did it look at, and what did it manage to read?* — `CoverageId`, `RunCoverage`.
- *Did it finish, and may I compare against it?* — `RunState`, `RunComparability`.

A customer who lost it could still capture a forest and read the result once. He would lose the
ability to be told **what changed since last time**, because nothing would know what a last time
was, nor whether it was sound enough to measure against.

## Shape

**Two identities, and only one of them can be recomputed.**

`ProfileId` is a hash of the forest name and nothing else, so any caller holding the forest name
can rebuild it. That is what lets a bundle whose metadata was never written still land in the right
group. `CoverageId` hashes the domains the forest reported, and can only be read back from where
the run recorded it. They are kept apart for that reason: a combined identity would force a
half-filled value at exactly the places that recompute the profile, and a wrong key there silently
groups runs that must not be compared.

**Coverage varies two ways, and they are not alike.** Either a domain could not be fully read — a
failure nobody chose — or the forest itself changed shape. The predecessor could not tell these
apart, because an operator-set exclusion looked like both. There are no exclusions now:
[`0017`](../decisions/0017-capture-reads-the-whole-forest.md) removed them and capture reads the
whole forest.

**A partially read domain counts as failed.** `DomainReadOutcome` has five members and only
`Read` counts as success. A domain read in part is a hole of unknown shape, and nothing downstream
can see its edges.

**A domain left out is not a domain that failed, and neither is a domain nothing could reach.**
`DomainReadOutcome.ExcludedByChoice` and `DomainReadOutcome.ExcludedForWantOfCandidates` are held
apart from `NotRead` and from each other, per
[`0063`](../decisions/0063-excluded-never-looks-like-unreachable.md), which holds the distinction
wherever either appears and names the run's own record of what it covered. One is *we did not
look*, the second is *the forest named nothing to look at*, and `NotRead` is *we tried and could
not* — three different remedies. The cause lives in the outcome rather than in the reason text so
that a reader of coverage can tell them apart without opening another table. None of the three
counts as success.

**One vocabulary for what became of a run**, and every one of its six words is arrived at from
something observed rather than assumed. See the state table below.

**One answer to whether a run may be used.** `RunComparability` is the only component that
decides, and every door is expected to call it. The verdict is a closed set, so adding a situation
later makes the compiler name every place that has not been updated.

## The comparability outcomes

Decision [`0027`](../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md).
The order is part of the decision: the first match wins, and the sequence runs from the least
recoverable situation to the most. A run that both failed a domain **and** saw a changed forest
reports the failure, because that is the one the operator has to fix.

Three card shapes, named by `DriftCardShape`. **No result** means no comparison happened; it says
so, names a cause, and never renders as a pass. **Qualified** means a comparison happened and
something must be said alongside the numbers. **Measured** means the comparison ran over the whole
estate with nothing withheld, and it is the only shape permitted to say that nothing changed.

The situations themselves are `ComparabilityOutcome`, and the set is closed: adding one makes the
compiler name every door that has not been updated to handle it.

The table below sits between the two markers around it, so the test parses only the rows. It is
bound in both directions — an outcome in the code and not here fails the build, and so does an
outcome here and not in the code — and the shape in the third column is compared against the shape
the code actually produces.

<!-- OUTCOMES:BEGIN -->

| Situation | Outcome | Shape |
|---|---|---|
| This is the first audit of the forest | NoEarlierRun | NoResult |
| The earlier audit is no longer in the library | EarlierRunDeleted | NoResult |
| The earlier audit did not finish | EarlierRunNeverCompleted | NoResult |
| This audit did not read every domain in full | ThisRunDidNotReadEveryDomain | NoResult |
| The earlier audit did not read every domain in full | EarlierRunDidNotReadEveryDomain | NoResult |
| The forest gained or lost a domain between the two | ForestDomainSetDiffers | Qualified |
| Some graph analysis was withheld from one of them | GraphFindingsWithheld | Qualified |
| The two were produced by different major versions | DifferentMajorVersions | Qualified |
| Nothing qualifies the comparison | FullyComparable | Measured |

<!-- OUTCOMES:END -->

`NoEarlierRun` and `EarlierRunDeleted` share an outcome and not a cause, and so do
`ThisRunDidNotReadEveryDomain` and `EarlierRunDidNotReadEveryDomain`. In both pairs only one member
is something the operator can act on today, and merging them would send him to fix the wrong thing.

`ForestDomainSetDiffers` is qualified rather than refused. A decommissioned domain or a completed
acquisition is a legitimate change, and refusing across it forever loses remediation tracking at
the moment it is most wanted. The predecessor reasoned this out correctly in its comparison core
and then made it unreachable, because the only command that checked coverage refused every
mismatch.

## The run states

Decision [`0028`](../decisions/0028-one-run-state-vocabulary.md). Each is reached by the procedure
in the third column, in that order, and the mechanism the procedure leans on is decided in
[`0029`](../decisions/0029-a-run-that-ends-badly-says-so.md).

<!-- STATES:BEGIN -->

| State | Meaning | How it is observed |
|---|---|---|
| Sealed | The audit finished and its evidence is intact | The evidence file is present and its seal verifies |
| Damaged | The evidence is there and cannot be trusted | The evidence file is present and the seal is absent, unreadable or does not match |
| Failed | The audit ended in an error it recorded | No evidence file, and the run outcome file records a failure |
| Cancelled | The operator stopped the audit | No evidence file, and the run outcome file records a cancellation |
| InProgress | The audit is running now | No evidence file, no outcome file, and something holds the partial file open |
| Interrupted | The audit stopped without recording why | No evidence file, no outcome file, and nothing holds the partial file |

<!-- STATES:END -->

**Only a finished run has coverage.** `RunSummary.OfCompletedRun` and `RunSummary.OfUnfinishedRun`
make *sealed with no coverage* and *unfinished with coverage* unbuildable, which is what actually
prevents the predecessor's baseline defect rather than the runtime check that also exists.

**The outcome file records only a bad ending**, so `RunOutcome` has two members and no member for
success. A finished run is already saying it succeeded by having sealed evidence, and a second
artefact repeating that would be a second answer to one question.

## What each piece is called

`ProfileId.ForForest` is the only factory, and `ProfileId.Value` and `ProfileId.ForestFqdn` are
what it carries. `CoverageId.ForDomains` likewise, carrying `CoverageId.Value` and
`CoverageId.ForestFqdn`. The normalised domain set behind the hash is kept too, but it is internal:
gate 4 forbids a public member handing back a collection from a type that cannot say whether it
looked, and this list can never be empty so the ambiguity cannot arise — but that is a fourth kind
of exemption, and the allowlist says plainly that a reason which is not *a compiled table that
cannot fail* does not belong in it. Callers outside the assembly read the same domains from
`RunCoverage.Domains`, which carries `RunCoverage.AllDeclaredUnitsAreComplete` beside them.

`DomainCoverage.Read`, `DomainCoverage.PartiallyRead`, `DomainCoverage.NotRead` and
`DomainCoverage.Excluded` record what
became of one domain, carrying `DomainCoverage.DomainFqdn`, `DomainCoverage.Outcome` and
`DomainCoverage.Reason` — which is null only for a domain that was read, because a domain that was
read has nothing to explain. `RunCoverage.Of` sets them against the declaration, and carries
`RunCoverage.Declared`, `RunCoverage.Domains`, `RunCoverage.IncompleteDomains` and
`RunCoverage.AllDeclaredUnitsAreComplete`.

A forest is not only its domains. The configuration and schema partitions belong to the forest
rather than to any domain, so `RunCoverage.Of` takes their outcomes as well and carries
`RunCoverage.ForestPartitions` and `RunCoverage.UnreadForestPartitions` beside the domain pair;
`RunCoverage.AllDeclaredUnitsAreComplete` is true only when both are empty. Each is a
`ForestPartitionCoverage.Read` or `ForestPartitionCoverage.NotRead`, carrying
`ForestPartitionCoverage.NamingContextDn`, `ForestPartitionCoverage.Kind`,
`ForestPartitionCoverage.Outcome` and `ForestPartitionCoverage.Reason`, whose two states are
`ForestPartitionReadOutcome.Read` and `ForestPartitionReadOutcome.NotRead`.

There is no third state there, and no overload that omits the argument. A domain is many partitions
and can genuinely be read in part; each of these is one capture unit, which either completed or
ended the run. And every forest has exactly one of each, so unlike the domain list their
denominator is known without discovery — which means silence can be refused outright rather than
merely noticed. That matters because until this existed a run that never read the schema partition
still reported every domain as covered, and per
[`0014`](../decisions/0014-capture-reads-the-schema-partition.md) an unread schema partition is the
failure that stops any permission being resolved at all. This is
[`0035`](../decisions/0035-coverage-is-recorded-once-per-capture-unit.md) applied to the run model.

`RunCoverage.Sysvol` is the third thing held beside the domains, and it is unlike the other two.
Group Policy settings live in files on a share rather than in the directory, and per
[`0044`](../decisions/0044-sysvol-coverage-is-recorded-beside-the-capture-units.md) **a failure to
read them does not fail the run** — the first and only exception to fail-fast capture, taken because
permission problems on a file share are ordinary and a run that died over one policy folder out of
four hundred would be unusable in the field. So this is the one value here that genuinely varies
between bundles, and it is deliberately **not** part of `RunCoverage.AllDeclaredUnitsAreComplete`:
that flag is an internal check true in every bundle a reader can open, and merging a real verdict
into it would rebuild the defect `F-S29-3` was raised about.

It is required, with no overload that omits it, for the reason the forest partitions are: a default
of *none reported* would let a run that never attempted the share pass as though it had nothing to
report. `SysvolCoverage.Of` sets the policy outcomes against the policies the directory declared,
carrying `SysvolCoverage.Policies`, `SysvolCoverage.UnreadablePolicies`, `SysvolCoverage.Outcome`,
`SysvolCoverage.AllDeclaredPoliciesAreComplete`, `SysvolCoverage.PoliciesDeclared` and
`SysvolCoverage.PoliciesRead` — the last two being the figure a report puts in front of a reader,
*397 of 400 policies were examined*. Each policy is a `GpoCoverage.Read`,
`GpoCoverage.PartiallyRead`, `GpoCoverage.Unreadable` or `GpoCoverage.Unlocatable`, carrying
`GpoCoverage.GpoGuid`, `GpoCoverage.DisplayName`, `GpoCoverage.FileSysPath`, `GpoCoverage.Outcome`
and `GpoCoverage.Reason`. `GpoReadOutcome.Read`, `GpoReadOutcome.PartiallyRead` and
`GpoReadOutcome.Unreadable` are its three states, and `SysvolReadOutcome.Read`,
`SysvolReadOutcome.PartiallyRead` and `SysvolReadOutcome.NotRead` the share's.

**Naming the failures is the condition the whole arrangement was granted under.** `0035` gives the
right to record coverage to capture units alone; `0044` widens it by exactly one clause — a thing
that is not a capture unit may record coverage only where its incompleteness has knowable edges.
SYSVOL qualifies because the policy list comes from LDAP before a single file is opened, so a run
that could not read three folders knows which three, by name and identifier. A record that said
*partial* without naming them would fail the test it was admitted under.

`RunStateNames.Persist` writes a state down and `RunStateNames.Read` reads it back, returning a
failure rather than a state for anything it does not recognise. `RunStateReader.Observe` follows
the procedure above and returns a `RunStateObservation` carrying `RunStateObservation.State` and
`RunStateObservation.Detail`. `RunOutcomeFile.Write`, `RunOutcomeFile.Read`,
`RunOutcomeFile.PathIn` and `RunOutcomeFile.FileName` are the outcome file, whose contents are
`RunOutcomeContents.Outcome`, `RunOutcomeContents.Detail` and `RunOutcomeContents.EndedUtc`.

`RunSummary.OfCompletedRun` and `RunSummary.OfUnfinishedRun` build what the verdict reads:
`RunSummary.Profile`, `RunSummary.State`, `RunSummary.Coverage`, `RunSummary.MajorVersion` and
`RunSummary.GraphFindingsWithheld`.

`RunComparability.Evaluate`, `RunComparability.NoEarlierRun`, `RunComparability.EarlierRunDeleted`
and `RunComparability.MayBeBaseline` are the four ways to ask. The first three give a
`ComparabilityVerdict` carrying `ComparabilityVerdict.Outcome`, `ComparabilityVerdict.Shape`,
`ComparabilityVerdict.Explanation` and `ComparabilityVerdict.ComparisonMayProceed`; the last gives
a `BaselineVerdict` carrying `BaselineVerdict.IsEligible` and `BaselineVerdict.Explanation`.

## Dependencies

- **Depends on:** `BundleLayout` and `BundleSealing` for the observation procedure; nothing else.
- **Depended on by:** the run library, compare, acceptance import, the dashboard drift summary,
  baseline nomination, and the run driver that must write the outcome file.
- **Layering violations:** none. This removes one that exists in the predecessor, where *may this
  run be used* is answered entirely in the UI layer.

## What is owed

**F6 is half of a row.** Deciding a run's state from its directory is built. Reading a run's
recorded identity and coverage *out of the evidence database* is not, because the bundle's schema
is being rebuilt after review and this session was told to leave it alone. `RunStateNames.Read`
and `RunCoverage.Of` are the interpretation half and are ready for the row that queries.

**Nothing writes an outcome file yet.** `RunOutcomeFile.Write` exists and has no caller. The
obligation lands on whatever drives a run, at inventory row B20, and until it is met every badly
ended run reports as `Interrupted` — which is true, and less useful than it will be.

**Nothing calls `RunComparability`.** The rule is written once and the five doors that must adopt
it do not exist yet. That is the honest statement of where the rebuild is, and it is what the
surface register records against F17.

## Verified-safe

- **The comparison core's relaxation is reachable this time.** `ForestDomainSetDiffers` is
  qualified and `ComparisonMayProceed` is true for it, asserted directly.
- **No refused comparison can report that it may proceed**, asserted over every producible verdict
  rather than case by case, so an outcome added later cannot slip through as a pass.
- **Only `FullyComparable` is ever `Measured`**, which is the property that stops a refused
  comparison rendering as a clean pass.
- **Eligibility and comparability cannot disagree**, asserted by running both over the same runs.

## Findings

### F-S18-1 — decisions 0025 and 0026 were built on a mechanism removed eight days earlier

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** [`0025`](../decisions/0025-the-run-library-is-a-managed-root.md) and
  [`0026`](../decisions/0026-one-answer-to-whether-runs-may-be-compared.md) against
  [`0017`](../decisions/0017-capture-reads-the-whole-forest.md) and inventory row B3; confirmed
  against `next/src/SecureAD.Audit/Capture/CapturePlan.cs`
- **What happens to a user:** nothing yet, because it was caught before code. Had it not been,
  four of the drift card's eleven states would have been unreachable, and the document binding
  them would have passed while asserting situations nothing can produce — a check measuring
  nothing, which is the failure this rebuild names first.
- **Why it is this way:** both records were written in a session that read the run library's
  predecessor closely and read `0017` not at all, because `0017` is a capture decision and the
  session was about the library. Nothing connects the two.
- **Options:** answered by [`0027`](../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md).
- **Test cover:** `CoverageIdTests.NothingCarriesExclusionsAnyMore` asserts by reflection that the
  exclusion model has not come back.
- **Status:** REPAIRED 2026-08-12.

### F-S18-2 — the run state vocabulary was drafted before checking what a bundle can show

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `next/src/SecureAD.Evidence/BundleLayout.cs`, which states that an interrupted run
  and a running one are indistinguishable from outside
- **What happens to a user:** nothing; caught before code, again. Four of the six states would
  have been unreachable, which is the same defect as F-S18-1 one layer down and in the same
  session that recorded it.
- **Why it is this way:** the vocabulary was drafted from the predecessor's four enums and from
  what would be useful to an operator, without checking what the bundle can prove. It was put to
  the owner in that state, so he was asked to rule on a question that was not properly formed.
- **Options:** answered by [`0029`](../decisions/0029-a-run-that-ends-badly-says-so.md) — an
  outcome file and a liveness test, which make all six observable.
- **Test cover:** `RunStateReaderTests` reaches every state from a real directory.
- **Status:** REPAIRED 2026-08-12.

### F-S18-3 — decision 0019's partial-file rule was stranded under a supersession marker

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** [`0019`](../decisions/0019-the-bundle-carries-a-seal.md) reads
  `Superseded by 0020`, and `0020` restates only what the seal proves
- **What happens to a user:** nothing directly. The rename mechanism that decides whether a
  directory is a finished bundle survived only in code and in `BundleWriterTests`. A session
  reading `0019`, seeing *superseded* and moving on would have lost it.
- **Why it is this way:** `0020` superseded one part of `0019` and the status line could not say
  so.
- **Options:** `0029` restates the mechanism live, and `0019`'s status now names which part was
  replaced.
- **Test cover:** `BundleWriterTests` covers the mechanism; nothing binds the record.
- **Status:** REPAIRED 2026-08-12.

### F-S18-4 — the decisions index was missing two records

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `docs/decisions/README.md` listed 0001 to 0024 and neither 0025 nor 0026
- **What happens to a user:** nothing, but the index is how a reader finds out what has been
  decided, and two records that shape the run library were invisible from it.
- **Why it is this way:** the session that wrote them did not add them.
- **Options:** added, along with 0027, 0028 and 0029.
- **Test cover:** none. Nothing binds the index to the folder, and something should.
- **Status:** REPAIRED 2026-08-12; the missing test is owed.

### F-S18-5 — mutation-testing found a guard that was doing nothing

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** removing `run.State != RunState.Sealed` from `RunComparability.MayBeBaseline`
  failed no test
- **What happens to a user:** nothing. The check is redundant because `RunSummary`'s factories
  already make *sealed with no coverage* unbuildable. But it was written to prevent the
  predecessor's defect, and a reader would reasonably believe it was what prevented it.
- **Why it is this way:** the type was made safe after the check was written, and nobody noticed
  the check had stopped mattering.
- **Options:** the check is kept, with a comment saying it is redundant and why the factory guard
  is the one to protect. `ARunCannotClaimToBeSealedWithoutSayingWhatItRead` now binds the guard
  that does the work.
- **Test cover:** as above.
- **Status:** REPAIRED 2026-08-12.

## Open questions for the owner

**A point-in-time review is owed.** The owner asked for a document he can read in one sitting that
says where the product stands: what it does today, what each accepted decision decided in one line,
and where earlier decisions have been overtaken. Two findings in this session are exactly what such
a review exists to catch, and neither the records nor any test found them. Not started; recorded
here so it survives into the next session.
