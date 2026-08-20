# S-26 — Reconciling the documentation with what was built

## Scope

This session makes the tree's documents agree with the code and with the decisions that govern it,
and leaves the parts that describe live code **bound by a test** so this does not have to happen a
third time.

It is `F-S25-5`, raised and decided on 2026-08-13 and deliberately not absorbed into `S-25`. Five
documents were caught disagreeing with the code during that one session — `S-16`, `S-18`, `S-2`,
`SURFACE-REGISTER.md` and the README warning box — every one of them by a binding test firing. That
is the mechanism working. It is also the whole of its reach: **only bound documents are covered, and
[`F-S24-2`](../../history/S-24-the-audit-database-schema.md) already proved a binding cannot detect that a
document and the code agree with each other while both describe a design that was superseded.**

**Five things are owed.**

1. **The eight decisions that are `Accepted` with a correction written into them** —
   [`0003`](../../decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md),
   [`0004`](../../decisions/0004-unknown-counts-name-the-failed-phase.md),
   [`0008`](../../decisions/0008-live-verification-is-removed.md),
   [`0009`](../../decisions/0009-greenfield-in-place-with-the-bundle-as-seam.md),
   [`0015`](../../decisions/0015-a-bundle-names-a-pattern-it-never-explains-one-away.md),
   [`0017`](../../decisions/0017-capture-reads-the-whole-forest.md),
   [`0025`](../../decisions/0025-the-run-library-is-a-managed-root.md) and
   [`0026`](../../decisions/0026-one-answer-to-whether-runs-may-be-compared.md) — each read against
   every document that cites it. A record that is half live and half withdrawn is the shape a slice
   inherits a dead claim from, which is exactly how `F-S24-2` happened. **This is the highest-yield
   check and it goes first.**
2. **The six unbound slice documents.** [`S-17`](../../history/S-17-the-run-library.md) first, because it
   describes code that exists and nothing checks it. Then
   [`S-19`](../../history/S-19-the-point-in-time-review.md), and the four historical records —
   [`S-20`](../../history/S-20-what-a-bundle-stores.md), [`S-22`](../../history/S-22-what-the-old-app-does-with-the-data.md),
   [`S-24`](../../history/S-24-the-audit-database-schema.md) and [`S-25`](../../history/S-25-the-finished-schema.md).
3. **Every ledger row's status against what is actually built**, in
   [`WHAT-THE-OLD-APP-HAD.md`](../WHAT-THE-OLD-APP-HAD.md). A row reading `Done` for something that does not run, or
   `Not started` for something that does, is the ledger lying about the product.
4. **[`ARCHITECTURE.md`](../ARCHITECTURE.md), [`READING-ORDER.md`](../READING-ORDER.md) and the four
   `DESIGN-` documents** against the accepted decisions.
5. **A binding for every document that describes live code and has none**, so the sweep changes what
   happens next rather than only what is true today.

**A historical record is cross-referenced, never corrected.** `S-20`, `S-22`, `S-24` and `S-25`
record what was found at a moment, and `S-24`'s own rule is that a withdrawn finding is evidence of
how an error entered. Rewriting them destroys that. What *is* checked on them is their
**forward-looking claims** — where such a document says what will be built, the code can now
contradict it, and that contradiction is a finding.

**Produces:** the corrected documents, new bindings where they are owed,
`docs/next/S-26-[slug].md` recording what disagreed and why, and a finding for every disagreement
that turns out to be the product holding two positions rather than one sentence being stale.

**Out of scope.** The capture-to-bundle seam (**B9**, **B10**, **C15**) — that is the next building
session and this one must not start it. View definitions (**C2**). The suppression sidecar
(**C5**). Anything in branch A or D. **No production behaviour changes in this session**: if a
document and the code disagree and the code is wrong, that is recorded as a finding and handed to
the row that owns it, not fixed here.

## Read first

In order:

- [`docs/next/S-25-the-finished-schema.md`](../../history/S-25-the-finished-schema.md) — `F-S25-5` is this
  session's reason for existing, and `F-S25-1` to `F-S25-4` are the shape of what a real
  disagreement looks like as opposed to a stale sentence
- [`docs/next/S-24-the-audit-database-schema.md`](../../history/S-24-the-audit-database-schema.md) —
  `F-S24-2` is the failure this session exists to find the rest of: two governing documents
  describing different schemas, agreeing with the code and with each other, and both wrong
- [`docs/next/README.md`](../README.md) — §`When a document counts as documentation`, §`Tests`,
  §`The ledger`, §`How to continue this work`, §`How a session is started` and §`Status`
- [`docs/decisions/0032-a-decision-record-is-corrected-in-place.md`](../../decisions/0032-a-decision-record-is-corrected-in-place.md)
  — the rule that produced the eight half-corrected records, and the rule any correction made here
  must follow
- [`docs/decisions/0011-rebuild-documentation-is-written-fresh-and-bound-by-tests.md`](../../decisions/0011-rebuild-documentation-is-written-fresh-and-bound-by-tests.md)
  — what a binding is for, which is what item 5 is building more of
- [`docs/decisions/0033-nothing-inherited-is-definitive.md`](../../decisions/0033-nothing-inherited-is-definitive.md)
  — because a document inherited from the predecessor's design is exactly what may not be assumed
  correct
- [`docs/next/WHAT-THE-OLD-APP-HAD.md`](../WHAT-THE-OLD-APP-HAD.md) — every row's status column, which is item 3
- The existing bindings under `next/tests/SecureAD.Next.Tests/Documentation/`, which are the
  pattern any new one should follow rather than invent

## Rules

- **Read the decision, then the document, then the code — in that order, and all three.** Two of the
  three agreeing is what `F-S24-2` looked like from the inside. A document that matches the code is
  not thereby correct.
- **No production behaviour changes.** This session edits documents and adds tests. Where the code
  is what is wrong, record a finding against the row that owns it and stop.
- **A document is not the truth unless it says it decided something.** Only `docs/decisions/` with
  `Status: Accepted`, or a finding carrying an explicit **Decision:**, states the product's
  position.
- **Correct a decision record in place**, per [`0032`](../../decisions/0032-a-decision-record-is-corrected-in-place.md),
  leaving the original reasoning where it stands. Do not tidy away the error that produced it.
- **Do not rewrite a historical record.** Cross-reference it. Its forward-looking claims are fair
  game; its account of what was found is not.
- **Every new binding is mutation-tested in both directions** — it must fail when the document is
  wrong and pass when it is right — and the directions observed are recorded.
- **One session. Do not widen.** Anything found that is not documentation is recorded as a finding
  and not acted on. `S-24` was individually justified at every step and finished nothing.

## Finish by

- The eight corrected decisions and every document citing them agree, or the disagreement is a
  recorded finding naming which side is wrong
- `S-17` and every other document describing live code is bound by a test, and the binding has been
  mutation-tested in both directions
- No ledger row's status contradicts what is in the tree
- The `S-21` gap is explained: a prompt exists at
  [`sessions/S-21-the-security-descriptor-parser.md`](S-21-the-security-descriptor-parser.md) and
  there is no `S-21` slice document, and nothing records whether one was owed
- `docs/next/S-26-[slug].md` exists, recording every disagreement found, which side was wrong, and
  which were left as findings
- The build is green, with the new bindings passing and the whole suite still passing
