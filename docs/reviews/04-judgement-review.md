# Review 04 — Judgement execution and uncertainty

**Reviewed:** 2026-08-28  
**Reviewer/model:** GitHub Copilot  
**Baseline:** `review-baseline-2026-08-28` (`d36ddb4`)  
**Status:** Findings open; no production correction accepted by this document

## Executive summary

Judgement has a strong local design. It streams Evidence once, distinguishes not-applicable objects
from missing inputs, isolates a throwing rule, discards that rule's partial findings, commits each
rule atomically with its execution record, binds judgement to the Evidence seal, and keeps an empty
finding list meaningful by returning it beside rule executions.

Its main problem is that local rule completeness is treated as whole-audit completeness. `JudgingRun`
never consults capture scope or Derivation completeness. A sealed bundle with an excluded domain can
therefore produce `Completed`, and no finding means only that the rules found nothing in the objects
present—not that the declared audit scope was fully assessed. Future derived-fact rules cannot be
added safely because `RuleVerdict` can represent only missing LDAP attribute names, while the needed
uncertainty includes missing/stale derivation, partial closures, disputed provenance, unverified path
semantics, and unassessed partitions.

The two current unconstrained-delegation rules use the Microsoft-published UAC bit correctly and
partition user-shaped and computer-shaped accounts. However, their domain-controller suppression is
evadeable: any one of three signals suppresses the finding, two signals are writable, and the promised
signal-disagreement report does not exist. The current rule cards are explicitly quarantined
predecessor material, so SEC-010/011 also need current-product specifications under the repository's
new specification-first policy; SEC-011 severity is unresolved.

Additional defects mirror Derivation: judgement database/seal replacement is not pair-atomic and
malformed sealed metadata can escape typed refusal. Findings keyset paging lacks a total ordering key,
the Shell hides actionable degraded-rule details, and CLI never runs Judgement. These findings support
the existing conclusion: retain the layered architecture, but establish one cross-layer assessment
contract before adding rules.

## Architecture / data-flow map

```text
Shell NewAuditViewModel
  -> JudgingLauncher
     -> JudgingRun.Judge
        -> read Evidence seal
        -> BundleReader.Open
        -> RuleCatalogue.All (SEC-010, SEC-011)
        -> stream ObjectAttributes once
        -> Tally.Offer per applicable rule
           -> RuleVerdict: findings OR missing attribute names
           -> exception isolates/discards one rule
        -> JudgementWriter.Write per rule transaction
        -> Complete: state -> indexes -> checkpoint -> seal -> replace
     -> JudgementReader.Open/Read
     -> aggregate severity counts
  -> Shell completion wording / Assets findings grid

CLI
  -> capture -> derive
  -> no Judgement execution

Derivation
  -> not opened by JudgingRun
```

## Verified strengths

### S-01 — Empty findings remain distinguishable from no judgement

`StoredJudgement` carries findings beside every rule execution, and paged reads refuse a judgement with
no rule executions rather than returning a clean-looking empty page (`JudgementReader.cs:43-83,
203-258`). This is the correct shape for an audit product.

### S-02 — Rule failures are isolated without exposing partial results

A throwing rule is offered no further objects, its accumulated findings and counters are cleared, and
other rules continue (`JudgingRun.cs:245-314`). The store records the error and degrades the run.

### S-03 — Applicability and missing evidence are distinct

`RuleDefinition.IsAbout` filters by the complete `objectClass` chain before the rule runs. Applicable
objects with absent inputs become `Indeterminate`; unrelated objects become `NotApplicable`
(`RuleDefinition.cs:58-84`; `RuleExecution.cs:35-57`). This corrected a real-forest false degradation.

### S-04 — A judgement is bound to its capture

The writer records the Evidence seal and the reader refuses a mismatch before exposing findings
(`JudgementWriter.cs:56-121`; `JudgementReader.cs:123-181, 511-534`). This is the contract Derivation
currently lacks.

### S-05 — Current rule trigger is first-party anchored

Microsoft defines `ADS_UF_TRUSTED_FOR_DELEGATION` as `0x00080000` and states that a service running
under such a user or computer account can impersonate a client. Microsoft recommends identifying
non-domain-controller entities with unconstrained delegation and moving to constrained forms.

## Findings

## J-01 — Judgement ignores capture and derivation completeness

**Severity:** Critical  
**Confidence:** High  
**Release blocker:** Yes  
**Status:** Confirmed

### Evidence

`JudgingRun` opens the bundle and streams `bundle.StreamObjects().Objects`; it never reads the returned
`BundleObjects.IsComplete`, `BundleReader.ReadScope`, or `DerivationReader` (`JudgingRun.cs:93-151`).
The run state is derived solely from per-object rule verdicts. A bundle whose declared domains include
an excluded/unread domain can therefore produce `JudgementRunState.Completed` and an empty findings
list.

### Customer consequence

The product can say every rule reached a verdict when whole declared domains or derived relationships
were outside the input. “No findings” then overstates the assessed scope.

### Recommended correction

Create one Judgement input context containing validated Evidence scope, validated Derivation identity,
product-level completeness, and the object stream. Define assessment state separately from individual
rule execution. A rule may complete over available objects while the overall audit remains degraded.

### Validation required

- Excluded/missing domain and incomplete reconciliation cases cannot produce whole-audit `Completed`.
- Missing, stale or degraded Derivation is visible to every rule that declares it.
- Operator output names the unassessed scope.

## J-02 — RuleVerdict cannot represent derived or semantic uncertainty

**Severity:** Critical  
**Confidence:** High  
**Release blocker:** Yes, before any derived-fact rule  
**Status:** Confirmed

### Evidence

`RuleVerdict` carries findings plus `InputsNotCaptured`, defined only as LDAP display names
(`RuleContracts.cs:6-45`). It cannot represent a missing derivation, schema mismatch, partial closure,
unknown group type, disputed Microsoft sources, primary-group traversal uncertainty, or an unverified
possible root/path.

### Customer consequence

SEC-030 or another derived rule would have to flatten materially different reasons into strings, throw,
or silently treat Unknown as false. Each creates misleading findings or clean results.

### Recommended correction

Replace the string-only gap with typed rule outcomes and typed input bases. At minimum distinguish:
`Judged`, `NotApplicable`, `CouldNotJudge`, and `RuleError`; reasons should identify source kind
(Evidence attribute, scope, Derivation product, provenance/semantic basis), subject, code, and detail.
Derived facts must carry their own uncertainty into the verdict rather than relying on a global flag.

## J-03 — Rule declarations are not enforced against runtime behavior

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes, for adding rules  
**Status:** Confirmed

### Evidence

The gate proves every rule declares at least one unique attribute. `JudgingRun` does not verify that a
rule-reported missing input was declared, nor can it prove the rule reported every declared input it
read. A rule can return `CouldNotJudge(["undeclared"])`, or read an undeclared attribute and return a
clean verdict. The declaration tests remain green.

### Recommended correction

Move input acquisition out of rule implementations. Judgement should resolve each rule's declared
inputs into a typed package before invocation, so absence is computed centrally. Until then, validate
reported missing names are declared and add mutation/negative tests that read undeclared values.

## J-04 — A spoofable domain-controller signal can suppress both current rules

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes  
**Status:** Confirmed

### Evidence

`DomainControllerSignals.IsDomainController` is true when any of SERVER_TRUST_ACCOUNT,
`primaryGroupID` 516/521, or placement beneath `OU=Domain Controllers` is true. The latter two are
writable/movable. SEC-010/011 return no finding whenever this aggregate is true
(`UnconstrainedDelegationRules.cs:65-67`). Comments say disagreement is reported, but production search
finds no consumer of `SignalsDisagree` outside schema comments.

### Customer consequence

An unconstrained-delegation account can evade both rules by setting a DC-like primary group or moving
under the conventional OU, while the evidence disagreement is stored only inside a finding that was
suppressed and therefore never exists.

### Recommended correction

Write and accept current SEC-010/011 specifications. Separate “established DC” from “DC-like signals
disagree.” Suppress only under the accepted established basis; disagreement must produce its own
finding or make the delegation verdict indeterminate/loud. Do not use OU location as decisive identity.

## J-05 — SEC-010 and SEC-011 lack accepted current-product specifications

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes, before modifying or relying on the rules broadly  
**Status:** Confirmed

### Evidence

`docs/rules/SEC-010.md` and `SEC-011.md` explicitly state they are predecessor material and not
specifications for this product. Current code uses High severity for both, while predecessor material
classified SEC-011 as Critical. The Microsoft trigger is established, but applicability, DC identity,
severity, wording, evidence and uncertainty have not been accepted under the current specification-
first process.

### Recommended correction

Create reviewed current rule specifications in the new rules folder, verify every claim against
first-party sources, resolve SEC-011 severity with the owner, and only then revise implementation.

## J-06 — Judgement replacement is not atomic as a database/seal pair

**Severity:** Medium  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed

### Evidence

`JudgementWriter.Complete` overwrites `judgement.db.seal`, then overwrites `judgement.db`
(`JudgementWriter.cs:208-225`). A failure between operations leaves the prior database with the new
seal, contradicting the documented promise that the previous judgement survives until completion.

### Recommended correction

Use the same recoverable generation/manifest protocol selected for Derivation. Fault-inject before and
after every promotion step and require either the old or new pair to remain openable.

## J-07 — Malformed sealed judgement metadata can escape typed refusal

**Severity:** Medium  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed

### Evidence

`JudgementReader.Open` catches only `SqliteException`. Invalid enum or timestamp text in a correctly
sealed store throws parsing exceptions from `ReadDescription` (`JudgementReader.cs:148-181, 536-567`).
Similar later read paths parse stored enums without a typed corruption boundary.

### Recommended correction

Validate stored representations explicitly and convert expected malformed-store conditions into
specific `JudgementUnreadable` errors. A successful Open should guarantee required metadata can be read.

## J-08 — Findings keyset paging is not totally ordered

**Severity:** Medium  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed

### Evidence

Paging orders and resumes by severity rank, rule ID and distinguished name
(`JudgementReader.cs:279-311`). The schema's finding identity additionally includes subject kind/key and
object GUID, so multiple rows may tie on all paging fields (`JudgementSchema.cs:140-183`). SQL row order
inside that tie is unspecified; a page boundary can omit or repeat rows.

### Recommended correction

Include `finding_id` or the full stable finding identity as the final ORDER BY and page-mark field.
Add a test with multiple same-rule findings on the same DN spanning a one-row page.

## J-09 — Shell degradation output is honest but not actionable

**Severity:** Medium  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed

### Evidence

The store records each unfinished rule, missing input and affected count. `JudgingOutcome` carries only
aggregate state, summed judged count and findings by severity. The Shell says at least one rule could
not reach a verdict but does not identify which rule or why (`IJudgingLauncher.cs:16-22`;
`NewAuditViewModel.cs:1810-1822`).

### Recommended correction

Carry a bounded degradation summary containing rule ID, outcome, typed reasons and affected counts.
Link completion output to the detailed rule-execution view rather than forcing log/database inspection.

## J-10 — CLI and Shell execute different audit pipelines

**Severity:** Medium  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed

### Evidence

Shell automatically captures, derives and judges. CLI captures and derives, and supports standalone
`--derive`, but has no judging command or post-capture Judgement call. Identical audit intent therefore
produces findings in Shell and no findings in CLI.

### Recommended correction

After the shared workflow required by Review 03 exists, have both hosts invoke it. Add explicit offline
`--judge`/`--analyse` behavior only if needed; do not duplicate sequencing in `Program`.

## Source status and unresolved decisions

| Subject | Status |
|---|---|
| `TRUSTED_FOR_DELEGATION = 0x80000` | Established by Microsoft |
| Non-DC unconstrained delegation is risky | Established by Microsoft |
| DC exclusion basis under disagreeing signals | Current implementation unsafe; specification required |
| SEC-011 severity High vs Critical | Owner/product decision required |
| Derived-rule uncertainty vocabulary | Architecture decision required |
| Whether Evidence-only rules may run when Derivation is absent | Product policy decision required |

## Recommended correction order

1. Finish Reviews 05–07 before production changes.
2. Write and accept current SEC-010/011 specifications; resolve J-04/J-05.
3. Implement Review 03 Tier 3/4 reproductions for J-01, J-03, J-06 and J-08.
4. Define the cross-layer assessment context and typed uncertainty contract (J-01/J-02).
5. Persist corrected Derivation products and connect Judgement (Review 02 D-01/D-02).
6. Harden storage replacement/readers (J-06/J-07) with the shared artefact protocol.
7. Make Shell/CLI consume one workflow and expose actionable degradation (J-09/J-10).

## Files read fully

- All production files in `next/src/SecureAD.Judgement`
- Passive Evidence finding contracts and attribute-reading helpers
- Both executable rules and their tests
- Current/predecessor rule documentation and first-party verification register
- Relevant Shell and CLI launch/output paths
- All Judgement tests and relevant Shell/architecture tests

## Tools and external sources consulted

- Microsoft Learn: User-Account-Control attribute
- Microsoft Learn: Use the UserAccountControl flags to manipulate account properties
- Microsoft Defender for Identity: Unsecure Kerberos delegation assessment
- Microsoft Learn: Kerberos authentication troubleshooting guidance
- Microsoft Learn: Configure Kerberos delegation for group managed service accounts

## Validation performed

- Production call graph traced from Shell through persisted findings and UI queries.
- Runtime and repository references checked for Derivation use and signal-disagreement consumers.
- Current rules compared with tests, quarantined predecessor cards and Microsoft sources.
- No production or test code changed.
- Build/tests: deferred to publication validation because this review adds documentation only.
