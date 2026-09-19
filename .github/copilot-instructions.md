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

## Documentation — changed 2026-09-11, and the change is the point

**This is a hobby project that must be accurate, not a professional codebase with a documentation department.** The owner's time is the scarce resource. On 2026-09-11, 260 tests that existed only to prove a document and the code said the same thing were deleted, because they protected a second copy of the truth rather than the product.

- **Three documents are maintained and nothing else.** `docs/PUNCH-LIST.md` is the work queue. `docs/WHAT-THE-PRODUCT-IS.md` records decisions the owner has already made, so he is never asked twice. This file says how to work. Keep these three accurate.
- **A specification is not a description, and the difference decides whether it may be deleted.** A *description* says what the code does; the code says that better, so a document repeating it is a second copy of the truth and goes. A *specification* says what the code **must** do — including cases not built yet, alternatives that were rejected and why, and the outside sources a rule rests on. **None of that can be recovered from the code**, because code records the decision taken and never the ones refused. Specifications live in `docs/specs/` and are kept. **This rule exists because the 2026-09-11 cut deleted 7,216 lines of specification** — 100 acceptance criteria and the specification of every shipping security rule — **along with 24,000 lines of description, because they sat inside `docs/layers/`.** They were deleted for where they were, not for what they were; the commit weighed every test it touched and recorded the documents as folder counts. Restored 2026-09-12 as `P-187`. Before deleting a document, ask which of the two it is.
- **Reasoning goes in code comments and in the commit message.** That is where it is actually read, it cannot drift from the code beside it, and nobody has to edit around it later. Do not write narrative into a document.
- **docs/layers/, docs/reviews/, docs/corrections/ and docs/planned/ are gone.** They were unbound from the code on 2026-09-11 and deleted on 2026-09-12. Do not recreate them, and write their paths without backticks when history has to mention one.
- **docs/decisions/ and docs/rules/ are reference.** Read one when a question needs it. Never maintain them proactively. The rules cards describe the predecessor.
- **Punch-list entries are three sentences.** Detail belongs in the commit message.
- **Do not reintroduce a document that must be kept in step with code by hand.** That shape is what was just removed, and it is the same failure the product keeps finding in itself: two places answering one question, free to disagree.

## Tests keep the code honest, never a document

**The owner's decision, 2026-09-12**, and what gives the documentation regime above teeth.

- **A test may check code against code, or code against an outside authority.** Microsoft's published specifications, a recorded output of the predecessor, a frozen lab result. Those can tell you that you are wrong, which is the only thing a test is for. The `*MicrosoftAnchorTests` family is the clearest case and the most valuable material in the suite — it is not a documentation test, and it stays.
- **Do not write tests that compare a markdown/documentation file against the code, or two documents against each other; delete such tests when found.** A drifting document is a documentation problem. It is fixed by reading it, not by a failing build.
- **One exception, granted explicitly.** `StageStatusGateTests` holds **two** stage tables to the code: the run pipeline in `docs/WHAT-THE-PRODUCT-IS.md`, and the build order in `docs/ROADMAP.md` § *Where we are*. `next/tools/check-stage-status.ps1` is the same check as a diagnostic a person can run. Each row names a witness type that exists if and only if that stage is built, and both directions are asserted. The pipeline table claimed *two* judging rules for long enough that twelve more were built underneath it, and the roadmap carried stage 5 as *not started* after group expansion had shipped; a stale stage table misleads the owner about the state of his own product, which no other document here can do.

## When to stop and raise it

**The default is to keep moving.** Something that is wrong but contained gets written down as a finding, with a severity and a status, in `docs/PUNCH-LIST.md` — and the work carries on. Stopping for every defect is as damaging as stopping for none: it turns a session into a list of interruptions and the owner into an approver of things he is not positioned to judge.

**Five things stop the work.** In each case, say plainly what is wrong and propose the fix; do not hand over an open technical question.

1. **A check that passes while measuring nothing.** The worst category, because everything downstream of it looks verified and is not. This has happened twice: gate 5's original wording passed against all fourteen public types while nothing in the tree was reachable, and the S-2 document guard matched a renamed member by substring so a deliberately broken document did not fail it. Usually cheap to fix on the spot, and it must be fixed before anything relies on the check. See `docs/next/README.md` § Gates for the scanner self-test that every gate carries for this reason.

   **A third shape, found 2026-08-20 (`F-S44-2`): a closed loop of checks anchored to the wrong reference.** The captured attribute catalogue was covered by three sound test suites — the document matched the code, the code matched the rules, the rules matched the document — every check passing in both directions with negative controls, and the whole circle anchored to the set of rules already written. A rule nobody wrote was an attribute nobody missed, and fifteen attributes the predecessor captured were silently absent. **Ask what a set of checks is anchored to, not only whether each one is sound.** Anything *reassembled* rather than *ported* has no external anchor, and internal-consistency tests cannot supply one however thorough they are.
2. **The product would tell a customer something false.** Not unclear — wrong. An object attributed to the wrong container, a "found nothing" that was really "could not compute", a permission reported as safe that is not, a comparison that failed reporting that it matched. This is the one thing an audit tool cannot do, because a customer makes a security decision on the strength of it. Never deferred.
3. **A frozen value needs editing.** Golden hashes and classifier fixtures are recorded outputs of the old system, kept to prove the rebuild changed nothing. If one needs changing, either the old behaviour was wrong or the new one is, and that is a conversation. See `docs/next/README.md` § Tests: a golden value that needs editing is a finding, not a fix.
4. **A decision that gets more expensive every week it waits.** Naming, the shape of a public interface, where a component lands. Free at zero consumers and brutal at thirty-four — which is how the DN helpers ended up with three near-identical ways to ask one question, and why gate 5 could not be retrofitted onto the old tree. Raise these while they are still cheap.
5. **A decision only the owner can make.** What the product should say, what an AD administrator would expect, which risk is acceptable, what to prioritize. As above: tooling, libraries, test structure, code layout, whether to use one technique or another — these are yours. Decide, then explain what you decided and what it costs. Handing a technical trade-off to the owner is not collaboration; it is avoiding a decision he is not positioned to make. Even when a session brief says "decide X", present the decision and its options to him and wait for his answer before writing any code. Do not treat a brief's wording as delegation of product or design decisions.

## SecureAD Specific Guidelines

- **The predecessor is on this machine, under whichever profile is in use.** Two boxes, two paths, and both are correct: `C:\Users\jistrand\source\repos\razamus\SecureAD` on the dev box and `C:\Users\ba.admin\source\repos\razamus\SecureAD` in the lab. Check both before concluding it is absent. Read it read-only: it is history and evidence, never a design to copy wholesale — but where it solved a problem this rebuild has re-opened, it is the best evidence available, because it ran against the real forest.
- **The production forest's scale is recorded in [`docs/WHAT-THE-PRODUCT-IS.md`](../docs/WHAT-THE-PRODUCT-IS.md) § The forest this is built for.** Roughly 347,000 objects and 5.9 million access control entries across nine domains, against a laboratory of 8,383. **Measure against that shape before recommending any limit, threshold or default.** A figure taken only from the lab or from a small synthetic capture is not evidence about a customer forest.
- **Measure before optimizing, and say what the measurement showed.** Judging writes a per-phase breakdown to the run log for this reason. Three plausible causes were proposed for one slow phase in a single session and two were wrong; the timing data settled it in twenty seconds. **For SecureAD.Next performance investigations, preserve pre-existing uncommitted work and original evidence/measurement artifacts, and identify executable/build provenance for every timing. Use isolated sealed-evidence copies offline. Obtain explicit approval before optimization or new measurement-harness code. Preserve permission proof, counting semantics, explicit incompleteness, and generation binding; do not activate discovery, change production budgets, access live forests, recapture, delete originals, commit, or push without separate authorization.**
- For SecureAD explanations, orient the owner within the Stage 6 control-edge work and its Tier 0 purpose before discussing narrow requester fixes. Distinguish existing ownership findings, permission-derived control edges, and later chained paths to Tier 0. Explain incomplete captured evidence separately from unsupported analysis and proposed processing limits. Use Tier 0-relevant examples without implying arbitrary example group names are hard-coded product scope.
- **For SecureAD.Next Stage 6 work, start from current documented requirements and accepted decisions without asking the owner to restate them.** Present concrete bounded implementation scope and screen wording/grouping for explicit approval before editing. Use synthetic/offline verification only unless separately authorized; preserve frozen evidence/measurement artifacts and subsequent uncommitted work. Do not commit or push without a new request. Keep permission evidence separate from operations, credential extraction, takeover and completed Tier 0 paths.
- **For SecureAD.Next Stage 6 preparation, keep group-held permission counts independent of member and route counts, distinguish stored membership attribution from concrete requester authorization, preserve resource scope and explicit incomplete results, and retain historical tests, frozen hashes and measurement artifacts.** Production expansion budgets require measurements against the documented nine-domain forest shape, not small fixtures; discovery stays inactive without an approved budget.
- **Clean, readable code is a core purpose of the SecureAD.Next rebuild.** Corrections must replace the flawed production design rather than leave parallel old/new implementations, dead code, confusing fallback paths, or permanent transition scaffolding. Preserve historical evidence and meaningful verification separately; that preservation is not a reason to retain obsolete production code.
- **For SecureAD.Next, require zero backward compatibility because the product has never shipped.** Refuse older result formats rather than adding migrations, legacy readers, empty-result substitutes, or hidden analysis-replay fallbacks. Preserve original saved results and historical artifacts; regeneration requires separate approval.

## Ownership-Takeover Analysis

- For SecureAD ownership-takeover analysis, the owner approved automatic detailed ownership-takeover assessment for core Tier 0 plus identified controllers/dependencies, with explicit on-demand single-object assessment elsewhere using captured evidence. Scope must be definable automatically, without a user-maintained important-object list. This does not authorize live access, treating unassessed objects as safe, or declaring unresolved owner transitions proven. Do not treat this proposal as implementation approval or silently narrow basic ownership findings; define indirect Tier 0 relevance and persist generation-bound on-demand results before display.

## Repository Practices

- Preserve pre-existing uncommitted work and frozen historical evidence.
- Use bounded, validated sessions and update existing governing documents rather than creating session-history documents.
- Explain results in plain language for an AD/security administrator.
- For SecureAD, laptop and external-monitor checks belong to normal product verification. Do not create a separate monitor-check session or make it a prerequisite to continuing R2/R7/R8; keep unperformed checks recorded as outstanding rather than accepted.
- For SecureAD.Next, check the existing specifications and accepted decisions before presenting product behavior as an unanswered owner decision. In particular, explicit requester/target batches in the judging API do not imply a manual administrator-maintained selection list; the judgement specification already prefers permission/group-first derivation from captured evidence.

## Ownership Assessment

- **Reuse the existing authoritative Tier-0 definition for ownership assessment and future path analysis.** Do not introduce a separate ownership-specific Tier-0 list or duplicate the definition in another location.

## GitHub Actions CI Management

- **Do not block a session waiting for a GitHub Actions CI run to finish after pushing.** Push and carry on with the next piece of work. Check the CI result opportunistically instead — at the start of the next session, before building on top of a push, or when a clean-machine failure is actually suspected. The GitHub CLI is installed and authenticated, so `gh run list --branch main --limit 1 --json headSha,conclusion` gives the answer in one non-blocking call.

## SecureAD.Next Regression Work

- For SecureAD.Next regression work, mutation-test every new behavior check and explicitly rebuild before running the mutated code and again after restoring it. Keep fixtures focused so an unrelated defect cannot make a test pass with the intended fix removed.
