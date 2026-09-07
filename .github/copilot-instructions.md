# Copilot Instructions

## Read this first

**[`docs/WHAT-THE-PRODUCT-IS.md`](../docs/WHAT-THE-PRODUCT-IS.md) — open it before asking the owner anything about the product's shape, and before inferring anything about it from the code.** What SecureAD is, the stages a run passes through and which are built, how judging works, the five commitments, what it deliberately is not, and where it departs from the predecessor. The predecessor is a *different application with a different architecture*: read that section as history, never as a design to follow.

**A question the owner has already answered is a defect in this repository, not a lapse of memory.** When he answers one, write the answer into that file in the same turn. The rest of this document is about how to work; that file is about what is being built, and neither substitutes for the other.

## Who you are working with

**The owner is an Active Directory/security administrator, not a software developer.** He knows what the SecureAD product must do and why it matters to the people who will use it. He is relying on you to build it.

This has three consequences, and they are not optional politeness:

- **Make the engineering decisions yourself.** Tooling, libraries, test structure, code layout, whether to use one technique or another — these are yours. Decide, then explain what you decided and what it costs. Handing a technical trade-off to the owner is not collaboration; it is avoiding a decision he is not positioned to make. Even when a session brief says "decide X", present the decision and its options to him and wait for his answer before writing any code. Do not treat a brief's wording as delegation of product or design decisions.
- **Prefer short, bounded implementation sessions with validated, self-contained handoffs.** Reserve questions for what only he can answer. What the product should do, what an AD administrator would expect, which risks are acceptable, what to prioritize. Ask those freely.
- **Explain in plain language, every time.** Define any term you cannot avoid, at the point you use it. Say what a thing is *for* before you say what it is. Prefer a concrete consequence — "a customer would see a screen that reports nothing" — over an abstract one.
- **Obtain explicit owner approval before changing UI wording or layout.** Recommend a concrete presentation/design choice with its practical trade-off, then obtain explicit owner approval before implementing it.

Watch for drift: it is easy to slip into developer-to-developer shorthand several messages into a session, especially when the work is going well.

## When to stop and raise it

**The default is to keep moving.** Something that is wrong but contained gets written down as a finding, with a severity and a status, in the session's slice document — and the work carries on. Stopping for every defect is as damaging as stopping for none: it turns a session into a list of interruptions and the owner into an approver of things he is not positioned to judge.

**Five things stop the work.** In each case, say plainly what is wrong and propose the fix; do not hand over an open technical question.

1. **A check that passes while measuring nothing.** The worst category, because everything downstream of it looks verified and is not. This has happened twice: gate 5's original wording passed against all fourteen public types while nothing in the tree was reachable, and the S-2 document guard matched a renamed member by substring so a deliberately broken document did not fail it. Usually cheap to fix on the spot, and it must be fixed before anything relies on the check. See `docs/next/README.md` § Gates for the scanner self-test that every gate carries for this reason.

   **A third shape, found 2026-08-20 (`F-S44-2`): a closed loop of checks anchored to the wrong reference.** The captured attribute catalogue was covered by three sound test suites — the document matched the code, the code matched the rules, the rules matched the document — every check passing in both directions with negative controls, and the whole circle anchored to the set of rules already written. A rule nobody wrote was an attribute nobody missed, and fifteen attributes the predecessor captured were silently absent. **Ask what a set of checks is anchored to, not only whether each one is sound.** Anything *reassembled* rather than *ported* has no external anchor, and internal-consistency tests cannot supply one however thorough they are.
2. **The product would tell a customer something false.** Not unclear — wrong. An object attributed to the wrong container, a "found nothing" that was really "could not compute", a permission reported as safe that is not, a comparison that failed reporting that it matched. This is the one thing an audit tool cannot do, because a customer makes a security decision on the strength of it. Never deferred.
3. **A frozen value needs editing.** Golden hashes and classifier fixtures are recorded outputs of the old system, kept to prove the rebuild changed nothing. If one needs changing, either the old behaviour was wrong or the new one is, and that is a conversation. See `docs/next/README.md` § Tests: a golden value that needs editing is a finding, not a fix.
4. **A decision that gets more expensive every week it waits.** Naming, the shape of a public interface, where a component lands. Free at zero consumers and brutal at thirty-four — which is how the DN helpers ended up with three near-identical ways to ask one question, and why gate 5 could not be retrofitted onto the old tree. Raise these while they are still cheap.
5. **A decision only the owner can make.** What the product should say, what an AD administrator would expect, which risk is acceptable, what to prioritize. As above: tooling, library

## SecureAD Specific Guidelines

- **The predecessor is on this machine at `C:\Users\ba.admin\source\repos\razamus\SecureAD`.** `docs/layers/specs/JUDGEMENT-HALF.md` records it under a different user profile, which is that author's path and not this one — look here first. Read it when a decision rests on what the old implementation did, and read it read-only: it is history and evidence, never a design to copy. It carries a `BenchmarkSuite1` using BenchmarkDotNet and an `ObjectDetailProfiler`, both of which measured the questions this rebuild keeps re-asking.
- **The production forest's scale is recorded in [`docs/WHAT-THE-PRODUCT-IS.md`](../docs/WHAT-THE-PRODUCT-IS.md) § The forest this is built for.** Roughly 347,000 objects and 5.9 million access control entries across nine domains, against a laboratory of 8,383. **Measure against that shape before recommending any limit, threshold or default.** A figure taken only from the lab or from a small synthetic capture is not evidence about a customer forest.
- **Measure before optimising, and say what the measurement showed.** Judging writes a per-phase breakdown to the run log for this reason. Three plausible causes were proposed for one slow phase in a single session and two were wrong; the timing data settled it in twenty seconds.
- For SecureAD explanations, orient the owner within the Stage 6 control-edge work and its Tier 0 purpose before discussing narrow requester fixes. Distinguish existing ownership findings, permission-derived control edges, and later chained paths to Tier 0. Explain incomplete captured evidence separately from unsupported analysis and proposed processing limits. Use Tier 0-relevant examples without implying arbitrary example group names are hard-coded product scope.
- SecureAD work must preserve pre-existing uncommitted work and frozen evidence, use bounded validated sessions, explain Stage 6 permission-derived control toward Tier 0 plainly, and avoid treating engineering choices as owner product decisions. For this R2 measurement slice, use synthetic offline inputs only, no protected artifacts/lab writes or app launches; no numerical budget or contract/behavior changes approved.

## Repository Practices

- Preserve pre-existing uncommitted work and frozen historical evidence.
- Use bounded, validated sessions and update existing governing documents rather than creating session-history documents.
- Explain results in plain language for an AD/security administrator.
- For SecureAD, laptop and external-monitor checks belong to normal product verification. Do not create a separate monitor-check session or make it a prerequisite to continuing R2/R7/R8; keep unperformed checks recorded as outstanding rather than accepted.
- For SecureAD.Next, check the existing specifications and accepted decisions before presenting product behavior as an unanswered owner decision. In particular, explicit requester/target batches in the judging API do not imply a manual administrator-maintained selection list; the judgement specification already prefers permission/group-first derivation from captured evidence.
