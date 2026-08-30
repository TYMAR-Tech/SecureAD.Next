# Wave 0 — Production-proof acceptance baseline

**Branch:** `correction/wave-0-production-proof`  
**Starting review synthesis:** `a4669af`  
**Status:** Eight expected failures; one passing offline journey scaffold

## Purpose

These tests turn the highest-priority repository-review findings into executable acceptance criteria.
They use real production stores/coordinators at the boundary where the defect occurs. They are expected
to fail until their correction wave is applied.

## Expected failing tests

| Review finding | Test | Expected current failure |
|---|---|---|
| E-C01 | `AConnectionFailureAfterOnePersistedPageRestartsWithoutDuplicatingTheAttempt` | Restart reaches `BundleCaptureSink.BeginPartition` with the abandoned domain partition still open after 1,000 objects were persisted. |
| D-03 | `Stage2a_ADerivationCopiedBesideDifferentEvidenceIsRefused` | `DerivationReader.Open` succeeds because it verifies only the derivation seal and never compares the Evidence seal. |
| D-05 | `Stage2a_MissingDeclaredDomainMakesReturnedAndStoredStateDegraded` | `Stage2aRun` returns `Completed` although persisted completeness is false. |
| K-01 | `WhenAnAceFallsOutsideTheDeclaredAclSize_ThenItIsNotParsed` | Parser accepts an ACE beyond the ACL's declared byte boundary. |
| K-02 | `AGenericBitStoredInAnAceIsNotReportedAsTheMappedRightsItWouldHaveRequested` | Classifier expands stored `GENERIC_ALL` and reports mapped rights as `Dangerous`. |
| J-01 | `AnExcludedDeclaredDomainMakesTheJudgementDegraded` | Judgement returns `Completed` because it ignores Evidence scope. |
| H-02 | `ACompletedDerivationDoesNotClaimUnpersistedClosuresWereCompleted` | Shell says every closure completed although closures are not persisted. |
| H-03 | `StoppingDuringDerivationSaysTheEvidenceWasAlreadySealed` | Shell says the run recorded why it stopped and omits that Evidence was already sealed. |

## Passing journey scaffold

`OfflineAuditJourneyTests.CapturedEvidenceIsDerivedJudgedAndReadBack` composes:

```text
ControllerModel + in-memory SYSVOL
-> CaptureRun
-> sealed Evidence
-> Stage2aRun
-> sealed Derivation
-> JudgingRun
-> sealed Judgement
-> JudgementReader finding
```

Only the external directory and SYSVOL boundaries are modeled. Production stage coordinators and all
three SQLite artefacts are real. Later waves extend this test with persisted derived facts, typed
uncertainty, host-neutral workflow and operator outcomes.

## Deferred reproductions

### CLI derivation failure exit status (H-05)

`Program.Main` and stage construction are private/concrete. Injecting failure now would require a
test-only branch or reflection around private methods, neither of which proves the future production
workflow. Add this process-level test when Wave 7 introduces the shared host-neutral workflow and a
controllable stage seam.

### CLI post-seal global fault wording (H-06)

Requires the same workflow seam to inject a fault after capture has returned a sealed bundle. Test the
published executable and assert stdout/stderr plus exit code.

### RunCompletionReader SQLite sidecars (E-C05)

Needs a provider/filesystem reproduction, including read-only media and clean WAL-mode database. This is
not an expected failing unit test until behavior is measured.

### BundleAssetSource same-path replacement (H-09)

Needs Windows/SQLite file-replacement behavior measured while a reader holds an immutable connection.
Define whether the UI pins a generation or refreshes before writing the acceptance test.

### Atomic analysis-store replacement (D-06/J-06)

Requires a production fault-injection boundary or generation/manifest design. Wave 3 should add crash-
point contract tests before implementing promotion.

## Running this baseline

Run the eight named tests together and expect `0 Passed, 8 Failed`. Run
`CapturedEvidenceIsDerivedJudgedAndReadBack` separately and expect it to pass.

A later correction is accepted only when its mapped test passes for the intended behavior and the full
suite remains green. Do not weaken these assertions to match current output.
