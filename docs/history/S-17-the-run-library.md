# S-17 — The run library

**Type:** slice
**Reviewed at commit:** `20fb93a4`
**Size:** 12 source files and 6 map and design documents read, no code written
**Date:** 2026-08-12

## What it does

The run library is how an operator finds a past audit again. It lists the runs that exist, names
them, nominates the one that later runs are measured against, deletes the ones that failed, and
resolves every caller-supplied path before acting on it.

A customer who lost it would still be able to capture a forest and read the result once. They would
lose the ability to say *what changed since last time*, because nothing would know what a last time
was.

This session decided where a bundle lives and what a baseline belongs to, and did not write code.

## Shape

Two identities, and only one of them carries domains.

- `ProfileId` is a hash of the forest FQDN and nothing else. It answers **same target**. It is a
  pure function of the forest, so a bundle whose metadata was never written can still be placed in
  the right group.
- `CoverageId` is a hash of the declared domain set plus the applied OU exclusions. It answers
  **same evidence**, and it hashes what the run *declared* rather than what it achieved.
  **— The exclusion half is withdrawn 2026-08-13 in `S-26`.** See the retraction below: the rebuild's
  `CoverageId` hashes the declared domains and nothing else.

Above them sits an attestation ladder. Excluding a domain requires the operator to state which of
two things is true, and both statements are enforced. *This domain is populated and I am excluding
it anyway* is recorded degraded and costs the run its baseline eligibility. *This domain holds
nothing of security value* is tested after capture against the members the forest actually
reported, and a falsified claim is recorded as what it turned out to be rather than as what was
claimed, costing eligibility the same way.

The consequence is the load-bearing one for this session: **every run that can ever be a baseline is
either a full-forest run or a run whose only exclusions were verified genuinely empty.**

> **Retracted 2026-08-12, in session S-18.** The two paragraphs above describe the predecessor, and
> this session read them as describing the rebuild. They do not.
> [`0017`](../decisions/0017-capture-reads-the-whole-forest.md) removed operator-configurable
> exclusion eight days earlier and named the exclusion attestation among what goes with it; ledger
> row B3 is **Delete** and says the attestation has nothing left to falsify. There is no ladder in
> the rebuild, because there is nothing to exclude and therefore nothing to attest.
>
> The sentence in bold is wrong in the rebuild for a simpler reason than it gives: coverage cannot
> vary by operator choice at all. What replaces it is in
> [`0027`](../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) - a run
> may be a baseline only if it sealed and read every domain the forest reported. The conclusion
> `0025` drew from the ladder survives; the ladder does not.
>
> The retraction is stated rather than the paragraphs deleted, because this session's
> recommendations were built on them and a reader of `0025` and `0026` needs to know why their
> reasoning names something absent. It is the same failure `F-S17-4` records one section below -
> a claim taken from a summary rather than from the code - repeated in the same session that
> recorded it, against a decision record rather than against a map page.
>
> **Widened 2026-08-13 in `S-26`, as `F-S26-1`.** The retraction above stopped one bullet short. The
> `CoverageId` bullet in `Shape` still said the identity hashes *the applied OU exclusions*, the
> `Dependencies` list still depended on *the attestation ladder in capture*, and `Verified-safe`
> still carried **OU exclusions are part of the coverage identity** as a checked fact. All three go
> with the ladder, and for the same reason. `SecureAD.Evidence`'s `CoverageId` hashes the declared
> domains and nothing else, says so on the type, and `CoverageIdTests.NothingCarriesExclusionsAnyMore`
> asserts by reflection that no exclusion member has returned.
>
> This is the shape [`F-S24-2`](S-24-the-audit-database-schema.md) warned about, caught one step
> earlier: a record left half live and half withdrawn, whose live half a later slice would have
> inherited as true.

## Dependencies

- **Depends on:** C (bundle layout and the run-control tables), ~~the attestation ladder in
  capture~~ (withdrawn in `S-26`; there is no ladder — see the retraction above), the coverage
  reader
- **Depended on by:** compare, acceptance import, the dashboard drift summary, report eligibility
- **Layering violations:** none introduced. The decision recorded in
  [`0026`](../decisions/0026-one-answer-to-whether-runs-may-be-compared.md) removes one that exists
  today, where the question *may this run be used* is answered entirely in the UI layer.

## Verified-safe

Things checked against the code and found correct, recorded so they are not re-investigated.

**These are findings about the predecessor's code**, at the paths given. Two of them describe
machinery [`0017`](../decisions/0017-capture-reads-the-whole-forest.md) removed and the rebuild
never built; they are marked below rather than deleted, because they are the evidence that the
mechanism worked before it was withdrawn.

- **The attestation dialog keeps both of its promises.** ~~*This run will not be usable as a
  comparison baseline* is enforced by `IsBaselineEligible`
  (`Core/Coverage/RunCoverageSnapshot.cs:140`) and refused before any write by
  `BaselineEligibility.Evaluate`, so a refusal leaves the existing baseline intact rather than
  clearing it and then failing. *This audit will check that claim against the rest of the forest* is
  `AttestationVerifier.Verify` (`Infrastructure/Storage/AttestationVerifier.cs:39`), which tests
  each claim of emptiness against `dim_unresolved_group_member`.~~ **Predecessor only, withdrawn in
  `S-26`:** there is no attestation dialog, verifier or ladder in the rebuild, and ledger row `B3`
  is `Delete`.
- **A degraded run can still be compared; it just cannot be the baseline.**
  `CompareCompatibilityValidator` returns `DegradedCoverage` with a warning rather than refusing,
  which is word for word what the dialog says.
- **Coverage hashes the declared set, not the achieved one** (`Core/Assessment/CoverageId.cs:19`),
  so a controller dying at hour two does not strand a run on its own permanent comparison island.
- ~~**OU exclusions are part of the coverage identity** (`Core/Assessment/CoverageId.cs:25`), because
  an excluded subtree drops objects and drops group members living under it.~~ **Predecessor only,
  withdrawn in `S-26` as `F-S26-1`:** the rebuild's `CoverageId` hashes the declared domains and
  nothing else, and `CoverageIdTests.NothingCarriesExclusionsAnyMore` asserts by reflection that an
  exclusion member has not returned.
- **Baseline clearing is scoped to the profile in both writers** —
  `RunLibraryService.Metadata.cs:431` and `RunMetadataService.cs:223` agree, which is not something
  this codebase can be assumed to do.
- **The run library groups by profile and shows a coverage line per run.** An earlier reading of
  `RunLibraryViewModel.BaselineRun` as library-wide was wrong; it is a member of `ProfileGroup`.
- **`ProfileId.FromComponents` does not exist**, and `ProfileIdTests` asserts its absence by
  reflection (`tests/SecureAD.Core.Tests/Assessment/ProfileIdTests.cs:108`).

## Findings

### F-S17-1 — the drift summary reports a refused comparison as a clean pass

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** `UI/ViewModels/MainViewModel.Drift.cs` (`DescribeDrift`, and `FindPreviousRunAsync`
  at `:112`); already recorded independently at `docs/map/G-compare.md` G13
- **What happens to a user:** a comparison the system **declined to perform** returns a result with
  every delta collection empty and `HasChanges` false, so the home screen prints *"No changes since
  the previous audit."* and sets the success flag, rendering the card as a pass. An operator who
  excluded a populated domain is told in the capture dialog that the run cannot be a baseline, and
  then shown an all-clear against that same baseline within the hour. The same applies one level
  down: a compare that withheld every graph delta, or left half the forest unassessed, produces an
  unqualified count string. The full compare window one click away shows all four notices correctly.
- **Why it is this way:** the summary was built from `CompareResult`'s counts, which is the natural
  thing to do if the compatibility verdict lives beside them rather than above them.
- **Options:** answered rather than left open —
  [`0026`](../decisions/0026-one-answer-to-whether-runs-may-be-compared.md) makes the card's shape
  follow the verdict rather than the counts, and forbids the success flag on a path where no
  comparison occurred.
- **Test cover:** none. `DriftSummaryTests` is named for this and never calls `DescribeDrift`, which
  lives in `SecureAD.UI` and is unreachable from `SecureAD.Core.Tests`.
- **Status:** OPEN in the old tree, which is being deleted; answered for the rebuild by `0026` and
  owed to F17. Verified against the code 2026-08-12.

### F-S17-2 — baseline eligibility never checks run state

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `Infrastructure/Storage/BaselineEligibility.cs`, its caller
  `RunLibraryService.Metadata.cs:413`, and the command guard `RunLibraryViewModel.cs:263`
- **What happens to a user:** the component's own summary says it decides whether a *sealed* run may
  serve as baseline, and it reads coverage only. Neither its caller nor the button checks state
  either. So a failed, corrupt or interrupted run whose coverage rows happen to read eligible can be
  made the baseline of a forest. `CanCompareToBaseline` (`:372`) then requires a sealed baseline, so
  it reads false forever: the forest has a baseline it can never be compared against, and nothing
  explains why, because there was no refusal to explain.
- **Why it is this way:** the component was extracted to be shared between two doors, correctly, and
  the condition it was extracted around was coverage. State was checked at the doors it used to live
  in.
- **Options:** answered by `0026` — eligibility folds into the single comparability verdict, which
  reads state and coverage together.
- **Test cover:** none found for the state case.
- **Status:** OPEN in the old tree; answered for the rebuild by `0026` and owed to F10. Verified
  against the code 2026-08-12.

### F-S17-3 — five independent answers to whether a run may be used, and they disagree

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `RunLibraryViewModel.cs` at `:371`, `:432` and `CanCompareWith`;
  `ImportAcceptancesViewModel.cs:175`; `MainViewModel.Drift.cs:112`; `BaselineEligibility.cs`.
  Cross-checked against `docs/map/F-run-model.md` F17 and `docs/map/G-compare.md`
- **What happens to a user:** the rules are not merely duplicated, they differ. The drift path checks
  neither coverage nor eligibility. Two of the three library compare commands check only sealing.
  The one command that does check coverage refuses **every** mismatch, including the
  changed-exclusion case that `CompareCompatibilityValidator` Rule 3 was deliberately rewritten to
  permit — so an operator who decommissions a domain or finishes an acquisition loses remediation
  tracking across the transition, and the carefully reasoned relaxation in the comparison core is
  unreachable from the only door that asks.
- **Why it is this way:** each predicate was written at the doorway that needed it, which is cheap
  once and expensive five times.
- **Options:** answered by `0026` — one verdict, a closed set of outcomes so the compiler names every
  unhandled door, and every door calls it.
- **Test cover:** the individual predicates have UI tests; nothing asserts they agree.
- **Status:** OPEN in the old tree; answered for the rebuild by `0026` and owed to F17. Verified
  against the code 2026-08-12.

### F-S17-4 — this document's predecessor claimed one forest means one profile

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `docs/next/DESIGN-the-run-library.md`, Open section as written 2026-08-12
- **What happens to a user:** nothing directly, but it was the basis of a recommendation put to the
  owner in this session, and the recommendation was wrong. The claim reads the predecessor's
  identity model as one axis when it is two, which hides the fact that `CoverageId` already carries
  domains and already gates comparison. The owner caught it.
- **Why it is this way:** it was taken from a map summary rather than from the code, which is the
  failure mode `docs/next/README.md` records for 2026-08-12 and which this session repeated.
- **Options:** corrected in place, with the retraction stated rather than the sentence quietly
  removed.
- **Test cover:** none; no test binds that document.
- **Status:** REPAIRED 2026-08-12.

### F-S17-5 — the repository instructions described a member that does not exist

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `.github/copilot-instructions.md`, Database Schema Guidelines, against
  `Core/Assessment/ProfileId.cs` and `ProfileIdTests.cs:108`
- **What happens to a user:** nothing directly. The instructions told every session that
  `ProfileId.FromComponents` survived as a read-compatibility path, and contradicted themselves two
  sentences earlier by naming a different member as the only producer. A session acting on it would
  preserve a path that is not there.
- **Why it is this way:** written while the removal was in progress and not revisited.
- **Options:** corrected in place, naming the test that proves the absence.
- **Test cover:** `ProfileIdTests` proves the code side; nothing binds the instruction file.
- **Status:** REPAIRED 2026-08-12.

### F-S17-6 — a ledger row was destroyed by a partial-line edit, for the fourth time

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `docs/next/WHAT-THE-OLD-APP-HAD.md` line 85 during this session; the rule it violates is in
  `docs/next/README.md` and in the session prompt
- **What happens to a user:** nothing, but a ledger row is how a future session learns what was
  decided. The edit replaced a clause at the end of the C10 row and removed roughly seventeen
  hundred characters before it, leaving a fragment with one cell instead of seven. It was caught by
  a cell count run immediately after the edit, not by reading.
- **Why it is this way:** the rows are single lines of two thousand characters or more, and the
  editing tool does not handle a targeted replacement inside one reliably. The existing rule says
  replace rows whole, which is the right instinct and does not help when the tool is the failure.
- **Options:** the method used for the remaining four rows — replace the whole line by index in a
  script, guarded by an assertion that the line starts with the expected component id, and verify
  the cell count and `git diff --numstat` after every row. Recorded here so the next session does
  not rediscover it.
- **Test cover:** `InventoryCompletenessTests` would have caught it, and did pass afterwards. The
  fourth column check exists precisely because a row lost two cells once before.
- **Status:** REPAIRED 2026-08-12, and the working method recorded above.

## Open questions for the owner

None outstanding from this session. Three were put and answered: the managed root, the per-forest
baseline, and the drift states. The wording of the eleven state messages was offered and accepted as
defensible, and remains the owner's to edit — `0026` deliberately records the states and their
shapes rather than freezing the sentences, so changing a message is a string and a test.
