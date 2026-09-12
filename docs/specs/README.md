# Specifications — what the product must do

**A specification says what the code *should* do. A description says what the code *does*.** The
second is redundant with the code and was deleted on 2026-09-11. The first cannot be derived from
the code at all, and should never have gone with it.

These eighteen documents were deleted in commit `754f537` and restored on 2026-09-12, byte for byte,
on the owner's decision. They hold the acceptance criteria the product is judged against and the
specification of each security rule — including cases not built yet, alternatives that were rejected
and why, and the Microsoft pages each rule rests on. **None of that is recoverable from the code**,
because code records the decision that was taken and never the ones that were not.

## What is here

| | |
|---|---|
| [`JUDGEMENT-HALF.md`](JUDGEMENT-HALF.md) | 100 acceptance criteria, `AC-01` to `AC-99`. Stage 6 names six of them |
| [`JUDGEMENT-HALF-ACCEPTANCE.md`](JUDGEMENT-HALF-ACCEPTANCE.md) | Which criteria are met, and by what |
| [`rules/`](rules) | One specification per security rule, fourteen of them |
| [`effective-access.md`](effective-access.md) | Full principal-level effective access. Not built; cited by the Stage 6 specification |
| [`the-query-tool.md`](the-query-tool.md) | Not built |

The name `JUDGEMENT-HALF.md` describes a plan rather than its contents, and is kept because decision
records and punch-list entries cite it by name. Renaming it would break those.

## What inside them may be stale

**They are restored exactly as deleted, and have not been corrected.** Correcting them on the way
back would have lost the thing being recovered, and nobody can tell from here which sentences went
stale in the year they were written over.

Two kinds of claim inside are known to be wrong now:

- **Paths into `docs/layers/`.** Those documents described code and remain deleted, correctly. A
  link into that folder points at something that is gone and is not coming back.
- **Enforcement claims.** A specification saying a gate holds some property may be naming a test
  deleted in the same cut. `docs/next/README.md` § Gates is the current record of what is enforced.

**Read these for the requirement and the reasoning. Read the code for what was built, and
`docs/next/README.md` for what is checked.**

## Why they were lost

The cut of 2026-09-11 was aimed at documents that re-describe the code, and at the tests holding
those documents to it — a sound rule, with `F-S44-2` as its evidence: three test suites agreeing in
both directions while fifteen captured attributes were silently missing.

**These files were deleted for where they sat, not for what they were.** They lived under
`docs/layers/`, and that folder was removed whole. The commit reasoned carefully about every test it
touched and recorded the document deletions as folder counts, so nothing ever weighed a
specification against the rule being applied. Roughly 7,216 lines of specification went out with
about 24,000 lines of description.

The rule that prevents a repeat is in `.github/copilot-instructions.md`, and the loss is recorded as
`P-187`.
