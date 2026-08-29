# Review 03 — Test architecture and false-green risks

**Reviewed:** 2026-08-28  
**Reviewer/model:** GitHub Copilot  
**Baseline:** `review-baseline-2026-08-28` (`d36ddb4`)  
**Status:** Findings open; no production or test correction accepted by this document

## Executive summary

The test suite is extensive, thoughtful, and unusually explicit about what many checks do not prove.
It contains strong pure-logic tests, SQLite round trips, modeled LDAP behavior, Shell state tests,
architecture boundaries, documentation consistency checks, negative controls, scanner self-tests, and
Microsoft-anchor fixtures. These controls have found real defects and are worth retaining.

The suite's weakness is not a lack of tests. It is a missing level of composition. At the baseline it
contains 1,891 `[Fact]` methods and 129 `[Theory]` methods across 184 C# files, but only one directory
named `EndToEnd`, one process-launch reference, and no test that runs the product journey from capture
through derivation and judgement to an operator-visible answer. The highest composed tests stop at
separate boundaries: modeled capture to sealed Evidence, hand-built Evidence to Judgement, direct
Stage 2a components, or fake launchers to Shell view models.

That structure explains the defects in Reviews 01 and 02. The retry loop passed against a permissive
recording sink while the production sink could not restart. Protected and latent algorithms passed
while Stage 2a discarded their outputs. Reconciliation existed and had tests around its ingredients
but had no production caller. Shell tests accepted preassembled outcomes and therefore could not see
that persisted completeness was dropped.

The suite should not be replaced. It should be completed with contract tests for every shared fake,
persisted product round trips, subsystem composition tests, one full offline product journey, and a
small real-environment confirmation layer. Corrections should not begin until the relevant failure can
be reproduced at the lowest test tier capable of observing it.

## Test-suite inventory

| Area | C# files | Facts | Theories | Predominant boundary |
|---|---:|---:|---:|---|
| Architecture | 38 | 130 | 15 | Reflection, IL and source shape |
| Documentation | 35 | 240 | 13 | Repository text and declaration consistency |
| Kernel | 29 | 417 | 64 | Pure algorithms/parsers and anchor fixtures |
| Evidence | 24 | 355 | 23 | SQLite writer/reader components |
| Shell | 12 | 332 | 4 | View models against interface fakes |
| Connect | 12 | 125 | 2 | Modeled forest/controller behavior |
| Derivation | 11 | 113 | 0 | Algorithms and derivation store components |
| Capture | 7 | 71 | 7 | Modeled LDAP channel and capture loop |
| Judgement | 5 | 69 | 0 | Rule/store components; Evidence-to-Judgement |
| Sysvol | 2 | 11 | 0 | In-memory file-share model |
| EndToEnd | 1 | 10 | 0 | Modeled CaptureRun to sealed Evidence |
| CLI | 1 | 18 | 1 | Argument parser only |

The project targets `net10.0-windows`/x64 and references every production assembly. It has no xUnit
collection fixtures coordinating shared integration resources. The suite contains one process-launch
reference; normal CLI tests invoke `CommandLine.Parse` rather than launching the executable.

## Verified strengths

### S-01 — Many tests state their proof boundary accurately

`ControllerModel` explicitly says it proves the documented rule rather than the wire
(`ControllerModel.cs:80-91`). `CaptureRunEndToEndTests` says it proves pieces fit each other, not that
they fit Active Directory (`CaptureRunEndToEndTests.cs:15-38`). `DirectorySearchGateTests` says a
source scan cannot prove the factory is called at runtime (`DirectorySearchGateTests.cs:20-30`). This
language is valuable because it prevents a local test from being mistaken for stronger evidence.

### S-02 — Architecture scanners include negative controls and self-tests

Source gates generally prove that production files were actually found and that their patterns match
a known occurrence. This directly addresses the historical failure where an empty scan passed cleanly
(`DirectorySearchGateTests.cs:105-141`; `ProductInvariantTests.cs:71-101`). Keep this practice.

### S-03 — The controller model encodes important LDAP distinctions

The model distinguishes absent paging controls, empty/fresh/repeated cookies, range retrieval, RootDSE,
base reads, continuation references, controller capabilities and partition scope. Its defaults were
corrected when real-bundle behavior disproved them (`ControllerModel.cs:80-180, 400-543`). It is a
useful protocol model, provided it is never treated as a domain controller.

### S-04 — Persistence components have meaningful round-trip tests

Evidence, Derivation and Judgement writer/reader tests verify seals, schemas, typed missing states and
on-disk values. Judgement additionally tests evidence-store identity mismatch. These tests make storage
contracts inspectable and caught the absence of derivation completeness before schema 3.

### S-05 — Real-run discoveries are routinely turned into regression tests

Test comments record concrete defects found in lab bundles and full runs: domain-scope behavior,
non-account objects degrading rules, SID collisions, escaped paths, and stale assumptions. The process
of converting field evidence into deterministic regression tests is sound.

## Findings

## T-01 — No test executes the complete product journey

**Severity:** Critical  
**Confidence:** High  
**Release blocker:** Yes, before coordinated correction waves  
**Status:** Confirmed

### Affected test boundaries

- `next/tests/SecureAD.Next.Tests/EndToEnd/CaptureRunEndToEndTests.cs`
- `next/tests/SecureAD.Next.Tests/Derivation/Stage2aRunTests.cs`
- `next/tests/SecureAD.Next.Tests/Judgement/JudgingEndToEndTests.cs`
- `next/tests/SecureAD.Next.Tests/Shell/NewAuditViewModelTests.cs`
- `next/tests/SecureAD.Next.Tests/Cli/CommandLineTests.cs`

### Evidence

Capture end-to-end tests compose `CaptureRun`, `BundleCaptureSink`, `BundleWriter` and a modeled LDAP/
SYSVOL environment, then stop at sealed Evidence. Derivation tests invoke algorithms or Stage 2a over
hand-built bundles/stores. Judging tests write a sealed bundle directly with `BundleWriter`, then run
Evidence-only rules. Shell tests use fake capture, derivation and judging launchers. CLI tests exercise
argument parsing but not `Program` as a process.

No test performs:

```text
modeled/fixture forest
→ production capture orchestration
→ sealed Evidence
→ production Stage2aRun
→ persisted/read-back derived facts
→ production JudgingRun consuming those facts
→ JudgementReader
→ operator-visible Shell/CLI summary
```

### Consequence

Every layer can be green while their contracts are disconnected. This is exactly how derivation could
run before judging while judging consumed none of it, and how persisted completeness could be omitted
from operator output.

### Recommended correction

Create one offline product-journey harness using production coordinators and stores, with only external
boundaries substituted: directory channel, SYSVOL, clock and UI host. It must use the same launchers or
a shared application workflow used by Shell/CLI, not duplicate their sequencing in the test.

### Validation required

- A planted derived-fact condition reaches a stored finding and visible summary.
- Missing/degraded derivation reaches a not-judged/degraded operator result.
- Evidence-only rules continue to run where allowed by the accepted policy.
- Cancellation and rerun preserve the last good artefacts.

## T-02 — Shared fakes are not held to production adapter contracts

**Severity:** Critical  
**Confidence:** High  
**Release blocker:** Yes, for fixes tested through those fakes  
**Status:** Confirmed

### Affected files

- `next/tests/SecureAD.Next.Tests/Capture/ControllerModel.cs:615-633`
- `next/src/SecureAD.Audit/Capture/BundleCaptureSink.cs:82-112`
- `next/src/SecureAD.Evidence/BundleWriter.cs:202-295`
- `next/tests/SecureAD.Next.Tests/Shell/ShellFakes.cs`
- `next/tests/SecureAD.Next.Tests/Sysvol/InMemorySysvolFileReader.cs`

### Evidence

The clearest counterexample is `RecordingSink`: `BeginPartition` only appends to a list, while the
production sink and writer reject a second open of the same partition. The restart test therefore
passed while production restart was impossible (Review 01 E-C01).

Shell fakes return preassembled outcomes and never create, seal, reopen or validate bundle artefacts.
The in-memory SYSVOL reader accurately models success/absence/denial but not SMB authentication,
filesystem races, path canonicalization, sharing violations or cancellation timing. These are valid
unit seams, but no common contract suite proves the fake and production adapter agree on shared
invariants.

### Consequence

A test can prove a coordinator against a more permissive dependency than production. Failures appear
only where stateful adapters meet, after the unit suite has already certified each side.

### Recommended correction

For each consequential seam, define behavioral contract tests and run them against both a controllable
reference fake and the production adapter where possible. At minimum:

- captured-object sink attempt/open/complete/abort state machine;
- reader/writer identity and malformed-input behavior;
- run launcher cancellation/rerun preservation;
- settings/run-library path and failure semantics;
- SYSVOL path/absence/access-denied distinctions.

A fake may expose extra scripting controls, but not weaken production invariants.

## T-03 — Direct algorithm tests are mistaken for delivered product tests

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes, for derived products  
**Status:** Confirmed

### Affected files

- `next/tests/SecureAD.Next.Tests/Derivation/ProtectedPrincipalDeriverTests.cs`
- `next/tests/SecureAD.Next.Tests/Derivation/LatentPrivilegeDeriverTests.cs`
- `next/tests/SecureAD.Next.Tests/Derivation/Stage2aRunTests.cs`
- `next/src/SecureAD.Derivation/Stage2aRun.cs:260-386`

### Evidence

Protected-principal and latent-privilege tests call the algorithms directly and assert their returned
objects. Stage-level tests assert that phase rows exist. Nothing asserts that the returned products
are persisted, reopened, or consumed. Stage 2a currently discards them, yet all these tests pass
(Review 02 D-01).

### Consequence

Correct algorithms create confidence in features the application does not deliver.

### Recommended correction

Every derived product needs three linked tests:

1. semantic algorithm test;
2. Stage 2a persistence/readback test;
3. consumer test proving a rule/operator result depends on the persisted fact.

The product claim is not complete until all three pass.

## T-04 — Runtime reachability is not systematically verified

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes, for coverage/completeness mechanisms  
**Status:** Confirmed

### Evidence

`ContinuationReferenceReconciliation` exists and its inputs are tested, but repository search finds no
production caller (Review 01 E-C02). Architecture gates can prove only that a mechanism is uniquely
located or has an allowed dependency; several explicitly acknowledge they cannot prove it is called.
No general reachability test starts from Shell/CLI composition roots and asserts that required
mechanisms execute.

### Consequence

Well-designed safety components can become dead code while source, documentation and unit tests stay
green.

### Recommended correction

Maintain a small list of customer-safety mechanisms requiring production-reachability tests. Exercise
them from the nearest real entry point and assert an externally visible effect, not merely a method
call. Examples: continuation reconciliation, evidence/derivation identity binding, completeness
propagation, seal verification, and rule input declaration.

## T-05 — Failure injection often occurs before meaningful state mutation

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes, for retry and replacement guarantees  
**Status:** Confirmed

### Evidence

The restart test fails the first request before the sink receives an object. It proves reconnect/retry
counting but not rollback after persisted state. Store tests cover interrupted files and normal
replacement but do not inject failure between seal and database promotion. Shell cancellation tests
throw from fakes before real artefacts exist.

### Consequence

The suite verifies control-flow reactions while missing the hard cases: cleanup, rollback, duplicate
prevention and preservation of the last good generation.

### Recommended correction

Failure tests must name and inject at state transitions:

- after partition reservation;
- after one page/object is persisted;
- during ranged retrieval;
- after transaction commit;
- after seal write and before promotion;
- after data promotion and before pointer/manifest promotion;
- after an earlier valid generation already exists.

At every point assert both the returned error and the complete on-disk/in-memory state.

## T-06 — Shell tests inject outcomes instead of proving persisted truth reaches the operator

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes, for truthfulness claims  
**Status:** Confirmed

### Affected files

- `next/tests/SecureAD.Next.Tests/Shell/ShellFakes.cs:528-653`
- `next/tests/SecureAD.Next.Tests/Shell/NewAuditViewModelTests.cs`
- `next/src/SecureAD.Shell/Services/DerivationLauncher.cs`

### Evidence

`FakeDerivationLauncher` and `FakeJudgingLauncher` return caller-supplied outcome records. This is the
right way to test view-model state transitions, ordering and exception handling. It cannot prove that
real launchers read truthful state from stores. Review 02 D-05 shows the real derivation launcher drops
`StoredDerivation.Completeness`, while fake-driven UI tests remain green.

### Consequence

The screen can correctly render the object it is handed while the production launcher hands it an
incomplete or contradictory object.

### Recommended correction

Retain fake-driven view-model tests, and add launcher-to-view-model integration tests over real bundle
artefacts. Treat launcher outcome records as public truth contracts: construct them from one stored
source of truth and test every degraded state through to user-facing wording.

## T-07 — CLI tests cover syntax, not executable behavior

**Severity:** Medium  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed

### Affected files

- `next/tests/SecureAD.Next.Tests/Cli/CommandLineTests.cs`
- `next/src/SecureAD.Cli/Program.cs`

### Evidence

All CLI tests invoke `CommandLine.Parse`. They do not launch `SecureAD.Cli`, capture stdout/stderr,
assert exit codes, send cancellation, or run `--derive` against a bundle. Parsing is well covered, but
operator-facing behavior in `Program` is not.

### Consequence

Exit-code, output wording, exception boundary, logging, and command dispatch regressions can ship while
CLI tests remain green.

### Recommended correction

Add process-level smoke tests for no/invalid arguments and offline `--derive`. Factor only unavoidable
external dependencies behind composition seams; keep parsing tests as fast unit coverage.

## T-08 — Source/document gates are tripwires, not semantic proof

**Severity:** Medium  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed limitation

### Evidence

Architecture gates scan project references, reflection surfaces, IL or source tokens. Documentation
tests compare files, tables, members and registered anchor-test names. Most include good self-tests and
state their limitations. Still:

- token scans cannot detect aliases, reflection, native calls or future equivalent APIs;
- unique-location checks do not prove the allowed implementation is invoked;
- document↔code consistency can form a closed loop anchored to an incomplete reference;
- the Microsoft register proves an anchor class exists, not that its assertions still establish the
  exact production claim.

### Consequence

A large green gate count can be read as broader behavioral assurance than the checks provide.

### Recommended correction

Classify these tests explicitly as structural. Each safety claim should link separately to its
semantic anchor, production-reachability test and real-environment confirmation where applicable.
Never use a structural gate as the sole acceptance test for customer-visible behavior.

## False-green taxonomy

| Pattern | Example | Required countermeasure |
|---|---|---|
| Permissive substitute | `RecordingSink` accepts repeated opens | Shared adapter contract tests |
| Component-only proof | Protected algorithm returns correct value | Persist/read/consume chain |
| Existence without reachability | Reconciliation has no caller | Entry-point reachability test |
| Split identity proof | Derivation writer stores evidence hash; reader never compares | Cross-bundle mismatch test |
| Injected presentation truth | Shell fake supplies `Completed` | Real launcher/store integration |
| Failure before mutation | Restart fails before first object | Post-mutation fault injection |
| Shared/internal oracle | Docs, code and tests agree with each other | Independent Microsoft/lab anchor |

## Required validation standard

A claim must be tested at the lowest tier capable of observing its real failure. Lower tiers remain
necessary but cannot substitute for higher ones.

### Tier 1 — Semantic unit

Pure parser, algorithm or value behavior against explicit examples and independent reference values.
No filesystem, database, network or UI.

### Tier 2 — Adapter contract

The same behavioral contract run against the controllable fake and production adapter where feasible.
Covers state transitions, errors, cancellation, ordering and ownership.

### Tier 3 — Persisted round trip

Production writer → seal → production reader. Includes schema refusal, identity binding, malformed
store behavior, uncertainty round trip and replacement/crash points.

### Tier 4 — Subsystem composition

Real coordinators and stores with only external systems substituted. Examples: modeled LDAP →
`CaptureRun` → Evidence; Evidence → Stage 2a → Derivation; Evidence+Derivation → Judgement.

### Tier 5 — Full offline product journey

One shared application workflow from modeled forest through capture, derive and judge to Shell/CLI
outcome. Uses production launchers/composition and validates operator-visible truth.

### Tier 6 — Real-environment confirmation

A disposable AD forest and representative filesystem/SMB environment confirm claims that a model
cannot: LDAP wire behavior, controller version differences, permissions, referral/cookie behavior,
confidential values, path handling and production scale. Record bundle, commands and expected output.

## Harness recommendations

1. Add an `ApplicationWorkflow`/equivalent production coordinator shared by Shell and CLI, so Tier 5
   tests execute real sequencing rather than reimplementing it.
2. Add fault-injection boundaries at attempt storage and artefact promotion, designed for production
   observability rather than test-only branches.
3. Build contract test suites for stateful interfaces, starting with `ICapturedObjectSink` and store
   identity readers.
4. Keep temporary artefacts on failure and print their paths; use unique directories so tests remain
   parallel-safe.
5. Tag or namespace tests by tier so CI can run fast tiers on every change and heavier tiers at
   appropriate gates.
6. Preserve Microsoft anchor tests, but add the exact production claim and consumer they support to
   the verification register.

## Recommended correction order

1. Create Tier 2 contract reproduction for Review 01 E-C01 before changing retry behavior.
2. Create Tier 3 mismatch/state tests for Review 02 D-03/D-05.
3. Build Tier 4 Evidence→Derivation and Evidence+Derivation→Judgement harnesses.
4. Build one Tier 5 offline product journey.
5. Implement correction waves from the synthesis review using those harnesses.
6. Add Tier 6 scripts/scenarios for claims that cannot be established offline.

## Files read fully

- `next/tests/SecureAD.Next.Tests/SecureAD.Next.Tests.csproj`
- Major shared models/fakes and fixtures in Capture, Connect, Shell and SYSVOL
- Current EndToEnd, Judging, Derivation, Shell and CLI test boundaries
- Foundational Architecture scanners/gates and representative Documentation tests
- Reviews 01 and 02 and relevant production implementations

## Validation performed

- Suite inventory measured from repository sources.
- Shared fakes compared with production adapter behavior.
- Repository-wide searches performed for process launches, collection fixtures, composition-root use,
  real launchers and complete workflow calls.
- Known Review 01/02 defects traced to tests that remained green.
- No production or test code changed.
- Build/tests: deferred to report-publication validation because this review adds documentation only.
