# S-44 — The questions only the owner can answer

Produces: decision records in `docs/decisions/`, and the *"What has not been discussed"* sections of
the area files that get written. Governing records: whatever this session decides.

**Taken at the owner's suggestion after [`S-43`](S-43-the-documentation-transition.md).** His words:
*"when it comes to questions that need my input lets dedicate a session to sprint through them. i
have a lot of experience with my old app so there is plenty i can answer up front. some may change
and we get to the section and implement it though."*

## Why this session exists

[`S-43`](../../history/S-43-the-documentation-transition.md) put the enforcement in place: an area
file cannot claim a capability without a test, cannot cite a record that is not there, and cannot
quietly omit its *"What has not been discussed"* section. **Six of nineteen areas are written.** The
other thirteen are not, and they cannot be written by the agent alone, because the section that
matters most in each is the list of things the agent must not guess at.

**Step 5 of `S-43` is blocked behind this session.** The surface register keyed to areas requires
every public type to be claimed by exactly one area, which requires all nineteen areas to exist.
Step 7 follows step 5. Nothing else in the transition is outstanding.

The owner ran the predecessor against real forests for fourteen months. Most of what is open is
answerable from that experience without a running window, and answering it cold is cheaper than
discovering it at the fourth screen.

## The one rule that makes this session stick

**Every answer becomes a decision record, however short.** By this repository's own rule, only a
record in `docs/decisions/` with `Status: Accepted` states the product's position; everything else
is discussion, and a future session is *required* to read it as argument. An answer that lands only
in a session document has not been decided — it has been discussed, and it will be re-argued.

**Revising an answer is not a failure of the session.** [`0057`](../../decisions/0057-starting-an-audit-is-a-modal-act.md)
reversed the status-bar answer given earlier the same day, and the reversal is visible in the record
rather than the first answer being overwritten. A revision costs one new record.

## Three legitimate answers, and the third is as useful as the first two

- **The answer.** It becomes a record.
- **"The old app did X and it was wrong because Y."** It becomes a stronger record, because it
  carries the reason.
- **"I need to see it running first."** It stays open, and the agent writes down *why* it is open, so
  a later session does not mistake it for an oversight and infer an answer.

The third is the right answer whenever the question is really about how something feels on screen.
Those are cheap to answer cold and expensive to be wrong about.

## Scope

**In.**

1. **The agent builds the agenda first**, grouped by area, each question stating why it is being
   asked now and what it blocks. Drawn from the fifty-seven records, the six written area files, the
   area-tagged ledger and [`DOCUMENT-COVERAGE.md`](../DOCUMENT-COVERAGE.md).
2. **Answer in this order**: questions blocking work about to be done; then questions that get more
   expensive the longer they wait — naming, the shape of a public interface, where a component
   lands; then the rest. The middle group is the one worth patience, because those are free now and
   brutal at thirty-four consumers.
3. **Write the records** as the answers come, not in a batch afterwards.
4. **Write the area files** the answers unblock, each with the owner's own *"What has not been
   discussed"* section.

**Questions already known to be waiting.** The agent's agenda will be longer; these are the ones
`S-43` surfaced and could not answer.

- **Can an operator stop a run in progress**, and what is the half-run left behind good for?
- **Does an exclusion carry forward** between runs, or is it re-attested each time?
- **May a run with an excluded domain be compared** to one without it?
- **What does `0049`'s attestation actually ask for**, where is it stored, and does it survive into
  the bundle? It has no code, no test and no screen.
- **`C27`, low-signal OU recommendation query.** Does [`0052`](../../decisions/0052-the-domain-is-the-only-unit-of-scope.md)
  remove its premise? It is the one ledger row left unjudged rather than guessed.
- **Is the captured attribute catalogue complete for rules not yet written?** Adding an attribute
  later means old runs cannot answer the new question.
- **What is owed about the ten unenforced session documents?** The binding practice stopped at
  `S-28`, so the newest half of the product is documented with the least protection.

**Out, deliberately.**

- **Any product change.** This session decides and records; it does not build.
- **Steps 5 and 7 of `S-43`.** They follow this session and are their own work.
- **Anything needing a running window.** That is an answer of *"I need to see it first"*, recorded as
  open with its reason.

## Where this starts

Read, in this order:

- [`docs/areas/README.md`](../../areas/README.md) — the nineteen areas and which six are written.
- [`.github/copilot-instructions.md`](../../../.github/copilot-instructions.md) § *Orient before
  proposing anything*.
- [`S-43`](../../history/S-43-the-documentation-transition.md) — what is enforced now, and the five
  findings it left.

**A note on searching this repository.** `git grep` and `git ls-files` are the only searches to
trust here; the built-in file search returns empty results for tracked files under `docs/`.

## Rules

- **Every answer becomes a record.** No answer lives only in prose.
- **The owner writes every *"What has not been discussed"* section.** The agent may draft the rest,
  and must mark its drafts as drafts.
- **The agent proposes questions; it does not present its list as complete.** A list of the agent's
  that looks exhaustive is the trap — the owner answers twenty and the one that mattered was never
  on the page. The agenda goes over as *"here is what I can see, what am I missing?"*
- **A question the agent can answer from the records or the code is not asked.** The owner's time is
  for what only he can decide.
- `§§ Tests` and `Gates` of [`docs/next/README.md`](../README.md) bind any code this session touches.

## Finish by

- Every answer given is an Accepted record, and every question deferred is written down with the
  reason it is still open.
- The area files unblocked by those answers exist, each passing `AreaFileGateTests`.
- `C27` is judged, or explicitly recorded as still open.
- The solution builds and the whole `SecureAD.Next.sln` suite passes.
- **The owner can say what is decided and what is open without the agent in the room.**
