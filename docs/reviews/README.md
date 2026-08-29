# Repository review program

This directory holds focused reviews of SecureAD.Next. The review pause exists because capture,
derivation, judging and the Shell are now substantial enough that a wrong shared assumption can
spread into dozens of rules, while few enough rules exist that correcting one is still cheap.

## Baseline

Every review in this cycle is performed against the tag named in `REVIEW-REGISTER.md`. A reviewer may
read the whole repository for context but reviews one bounded scope at a time.

## Authority

**A review is evidence and argument, not a product decision.** Under the repository instructions, only
an accepted record in `docs/decisions/` or a finding carrying an explicit `Decision:` line states the
product's position.

External AI agreement is not acceptance. Important claims are re-checked against production code and
primary sources before a finding is accepted, rejected or implemented.

## Evidence standard

A reviewer must:

- read relevant source, tests, specifications and accepted decisions in full where conclusions depend
  on context;
- trace important behavior through production call paths;
- distinguish direct test construction from production reachability;
- verify Microsoft/.NET/Active Directory claims against current first-party sources;
- preserve first-party source conflicts rather than silently choosing one;
- treat a green suite as evidence, not proof; and
- identify checks that can pass while measuring nothing or while anchored to an incomplete reference.

## Finding status

| Status | Meaning |
|---|---|
| `Open` | Reported and not yet verified |
| `Confirmed` | Reproduced against code/source; correction not yet accepted |
| `Needs evidence` | Plausible but primary evidence is insufficient |
| `Rejected` | Review claim disproved; reason recorded |
| `Accepted` | Product/architecture correction recorded authoritatively |
| `Fixed` | Implemented and validated; fixing commit/tests linked |

## Review order

1. Evidence and capture correctness/completeness
2. Derivation correctness and persistence
3. Test architecture and false-green risks
4. Judgement, rule execution and uncertainty
5. Kernel AD semantics and parsers
6. Shell/CLI reachability and operator truthfulness
7. Synthesis and implementation order

Performance and scale are reviewed separately after correctness, against production-shaped synthetic
workloads.
