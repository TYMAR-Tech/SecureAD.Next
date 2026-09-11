<!-- PREDECESSOR-MATERIAL:BEGIN -->
> **Predecessor material. Not a specification for this product.**
>
> This file was written against the previous SecureAD, and every code path, table and query in it
> describes that product. `rules.yaml`, `FindingsService`, `RuleEvaluatorHelpers` and the `dim_*`
> tables **do not exist here** and are not going to. Where this file says what a rule *does*, it is
> reporting what the old tool did, not what this one must do.
>
> Read it as a source, not an answer. The Active Directory reasoning is worth having; the
> implementation is not. In this product executable rules are `IRule` implementations in `SecureAD.Judgement`,
> registered in `RuleCatalogue.All`, resting on evidence stored by `JudgementWriter`, and
> reading only attributes declared in `CapturedAttributeCatalog`. What a rule is here is described
> in layers/judgement/what-a-finding-is.md.
>
> Nothing in here is held by any gate. It is quarantined rather than rewritten, per `P-101`.
<!-- PREDECESSOR-MATERIAL:END -->

# Rule verification card — template

<!--
HOW TO USE THIS TEMPLATE

1. Copy this file to `docs/rules/SEC-XXX.md` (replace `XXX` with the rule id,
   e.g. `SEC-004.md`). Never edit `_template.md` for a specific rule.
2. Fill in §1–§13 strictly in order. Earlier sections constrain later ones:
   - §1 catalog claim is verbatim from `rules.yaml`. Do not paraphrase.
   - §2 plain-English detection is written from §1 ONLY — do not look at the
     evaluator yet. This is what catches catalog drift.
   - §3 code references come from the evaluator. Compare §3 to §2; any divergence
     is logged in §12 with status `Accepted-with-known-limitation` or fixed.
3. Add at least one positive (§6) and one negative (§7) test PER post-SQL filter
   and PER exclusion. A 3-row §6 paired with a 6-row §5 is a coverage smell.
4. Edge cases (§8) start with the standard rows below; ADD rows for anything rule-
   specific. Do not delete rows even if N/A — write the resolution as `N/A — reason`.
5. Run the focused test filter and full FindingsServiceTests + RuleCatalogParityTests
   suite. Record exact counts in §10 (e.g. "Focused filter: 13 passing, 0 failing.
   FindingsServiceTests + RuleCatalogParityTests: 198 passing, 0 failing.").
6. Tag every §12 / §13 entry with an `[IMP-xxx]` code from
   `docs/rules/IMPROVEMENTS.md`. If no existing tag fits, add a new one to
   the taxonomy FIRST, then use it here.
7. §11 sign-off is the gate. Status moves from `Draft` to `Verified` only when
   every checkbox is `[x]` AND every §12 item is either resolved or explicitly
   accepted.

CONVENTIONS
- Section numbers are stable. Do not renumber.
- Resolved §12 / §13 items stay in the card untagged for historical context.
- Cross-card references are by section number, e.g. "Aligned with SEC-001 §12.1".
- Never assert "Verified" on a card whose focused test filter has a failure.
- One rule = one card. Do not bundle multiple rules into a single card.

REFERENCES
- Improvement-tag taxonomy: `docs/rules/IMPROVEMENTS.md`
- Parity-of-record tests:   `tests/SecureAD.Infrastructure.Tests/Findings/RuleCatalogParityTests.cs`
- Default test fixture:     `tests/SecureAD.Infrastructure.Tests/Findings/FindingsServiceTests.cs`
- Catalog source:           `src/SecureAD.Core/Findings/Rules/rules.yaml`
-->

> Predecessor verification card. Its code references describe the previous product; see the banner above.
> Status flows: `Draft` → `Verified` or `Defect-Found` or `Accepted-with-known-limitation`.

## Status

| Field | Value |
| --- | --- |
| Status | `Draft` |
| Reviewer | _name_ |
| Reviewed commit | _git short SHA_ |
| Review date | _yyyy-mm-dd_ |

## 1. Catalog claim (verbatim from `rules.yaml`)

```yaml
- id: SEC-XXX
  name: ""
  description: >-
    ""
  severity: ""
  category: ""
  remediation: >-
    ""
  mitre: ""
  tags: []
```

Source: `src/SecureAD.Core/Findings/Rules/rules.yaml` line _N_.

## 2. Intended detection (plain English)

> Restate, in one paragraph, what the rule should fire on. Written from §1 **only** — do not consult the evaluator yet. Any later divergence between §2 and §3 is captured in §12 (`[IMP-CAT-WORDING]`).

## 3. Code under review

| Reference | Path | Lines |
| --- | --- | --- |
| Evaluator dispatch | `src/SecureAD.Infrastructure/Findings/Evaluators/<file>.cs` | _N–N_ |
| Evaluator body | same file, `<method>` | _N–N_ |
| Helper(s) | `src/SecureAD.Infrastructure/Findings/RuleEvaluatorHelpers.cs` | _N–N_ |
| Coverage map entry | `src/SecureAD.Infrastructure/Findings/FindingsService.cs` `RuleCoverageRequirements["SEC-XXX"]` | _N_ |
| Edge / delegation finding builder | `RuleEvaluatorHelpers.cs` `CreateEdgeFinding` / `CreateDelegationFinding` | _N–N_ |

### 3.1 Effective SQL (copied from code)

```sql
-- paste exactly what the evaluator executes
```

### 3.2 Post-SQL filters (in C#)

- _exclusion 1_
- _exclusion 2_

## 4. Data dependencies

| Table | Columns read | Required coverage module |
| --- | --- | --- |
|  |  |  |

Verify the coverage map matches: every table above must map to a module listed in `RuleCoverageRequirements["SEC-XXX"]`. Note any transitive modules (e.g. `SecurityDescriptors` upstream of `ControlEdges`) and justify their presence.

## 5. Exclusions (and the reason each is correct)

| Exclusion | Mechanism | Justification |
| --- | --- | --- |
|  |  |  |

Not excluded (intentionally subject to review):

- _List anything the evaluator could plausibly exclude but does not. Justify each. Examples: broad SIDs, privileged-by-membership sources, deleted targets, non-`domainDNS` targets._

## 6. Positive cases (MUST fire)

| # | Scenario | Expected severity | Expected `Detail` substring | Test name |
| --- | --- | --- | --- | --- |
| P1 |  |  |  |  |

Coverage rule: at least one positive case per *non-trivial* code path in §3.2.

## 7. Negative cases (MUST NOT fire)

| # | Scenario | Why excluded | Test name |
| --- | --- | --- | --- |
| N1 |  |  |  |

Coverage rule: one negative case per row in §5 (exclusion → matching N row).

## 8. Edge cases considered

| # | Scenario | Resolution |
| --- | --- | --- |
| E1 | Deny ACE / `deny_cancelled = 1` |  |
| E2 | Inherited ACE |  |
| E3 | Deleted target object (`is_deleted = 1`) |  |
| E4 | Multiple matching edges for same (sid, target) |  |
| E5 | Coverage incomplete for required module |  |
| E6 | Cross-domain principal |  |
| E7 | Broad SID (`Everyone`, `Authenticated Users`, `Anonymous`) |  |
| E8 | Privileged-by-membership (transitive DA/EA) non-RID SID |  |

Add rule-specific rows as `E9`, `E10`, … Do not delete rows; mark `N/A — <reason>` when truly not applicable.

## 9. Output assertions (`Detail` and `ContextJson`)

The finding produced must include:

- `RuleId == "SEC-XXX"`
- `Severity == <value>`
- `SubjectSid` = source principal SID (or `""` for delegation-style findings)
- `TargetKind ∈ {"object_guid", "none"}`
- `TargetId` = target object GUID string (`D` format) or empty
- `SourceEdgeId` populated when derived from an edge
- `FindingKey == "SEC-XXX|{SubjectSid}|{TargetId}"`
- `Detail` contains: _required substrings_
- `ContextJson` non-null and contains:
  - `"rule_id": "SEC-XXX"`
  - _other required keys_

## 10. Test inventory

| Test | File | Status |
| --- | --- | --- |
|  |  | `missing` / `passing` / `failing` |

Verification runs (record exact counts; do not paraphrase):
- Focused filter (`<filter expression used>`): **_N_ passing, _M_ failing**.
- `FindingsServiceTests` + `RuleCatalogParityTests`: **_N_ passing, _M_ failing**.

## 11. Sign-off checklist

Status moves from `Draft` to `Verified` only when every box is `[x]` and every §12 item is resolved or explicitly accepted.

- [ ] Catalog claim and code agree in plain English (§2 vs §3 reconciled).
- [ ] Every exclusion in §5 has a documented reason.
- [ ] §6 has at least one positive test per non-trivial code path.
- [ ] §7 has at least one negative test per row in §5.
- [ ] Every test listed in §10 exists in the test fixture and passes.
- [ ] Focused test filter and full `FindingsServiceTests` + `RuleCatalogParityTests` both pass.
- [ ] `RuleCoverageRequirements["SEC-XXX"]` matches the tables read by the SQL.
- [ ] `Detail` and `ContextJson` are specific enough to remediate without opening SQLite.
- [ ] §12 reviewed; every item is resolved or `Accepted-with-known-limitation`.
- [ ] §13 items each carry an `[IMP-xxx]` tag from `docs/rules/IMPROVEMENTS.md`.

## 12. Defects / deferred items

> Tag each entry with an `[IMP-xxx]` code (see `docs/rules/IMPROVEMENTS.md`). Resolved items are kept for historical context and are intentionally untagged.

_None._

## 13. Improvement suggestions (not blocking)

> Tag each entry with an `[IMP-xxx]` code (see `docs/rules/IMPROVEMENTS.md`). If a needed tag does not exist, add it to the taxonomy first, then use it here.

_None._
