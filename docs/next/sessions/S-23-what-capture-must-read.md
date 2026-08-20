# S-23 — What capture must read, derived from the rules

## Scope

This session sizes the **captured attribute catalogue against the product**, rather than against how
far the rebuild has got.

`CapturedAttributeCatalog` currently holds roughly thirty attributes, and every one names a consumer
because `CapturedAttributeCatalogDocumentationTests` requires it. That gate is right and it is doing
the wrong job: **the consumer it accepts is a ledger row**, and a ledger row is a component of the
rebuild. Almost nothing in the rebuild is built, so the catalogue is bounded by the port's progress
rather than by what the sixty-two rules in `docs/rules/` actually need.

`F-S20-13` recorded some of the consequence and gave the reason as *"an attribute with no rule yet
written was correctly left out."* **The rules are written** — sixty-two of them, each with a card
carrying a Data dependencies section. They are unported, not unwritten. Every rule ported from here
will discover whether its data is present, and capture will be reopened each time.

This matters more than the usual reopening, because **capture is the one thing that cannot be
redone.** An attribute not requested is not in the bundle, is in no report, and nobody can go back
and re-read last quarter.

**Produces:** a catalogue derived from the rule cards, a gate that accepts a rule as a consumer, and
`docs/next/S-23-[slug].md` recording what was found.

**Out of scope:** porting any rule; the contents of the rule catalogue, which is a product question;
the evidence schema at C1, which this session exists to give a stable input to; and SYSVOL and Group
Policy capture, which are **B14** and **B15** and are known, tracked and deliberately not started.

## Read first

In order:

- [`docs/next/README.md`](../README.md) — §`Tests`, §`Gates`, §`The ledger`,
  §`How to continue this work` and §`Status`
- [`docs/rules/README.md`](../../rules/README.md) — what a rule card is and what each section holds.
  Then `FIRST-PARTY-VERIFICATION.md` in the same folder, which is **the precedent this session
  follows**: one atomic fact, verified once, mapped to *every* rule that consumes it, so that a
  changed value can be traced to everything needing re-checking
- [`DESIGN-what-makes-a-finding.md`](../../history/DESIGN-what-makes-a-finding.md) — the product's shape as
  derived from the catalogue: three kinds of rule, five gates, and the finding that about a third of
  the rules need no graph at all. **The three shapes decide what data each rule needs**, so read this
  before the cards
- [`S-8`](../S-8-captured-attribute-catalogue.md) — the catalogue as it stands, and the consumer
  column this session changes
- [`S-20`](../../history/S-20-what-a-bundle-stores.md) — `F-S20-13` in full, and the *Decisions taken* section,
  because what capture reads and what storage keeps were settled together
- [`0002`](../../decisions/0002-absent-view-means-degraded-run.md),
  [`0010`](../../decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md),
  [`0014`](../../decisions/0014-capture-reads-the-schema-partition.md) and
  [`0017`](../../decisions/0017-capture-reads-the-whole-forest.md)
- [`docs/next/WHAT-THE-OLD-APP-HAD.md`](../WHAT-THE-OLD-APP-HAD.md) — row **B2**, and rows **B14**, **B15**, **E21**,
  which are the SYSVOL work this session must not absorb

**Then read the cards.** All sixty-two, at their §4 *Data dependencies* and §3 *Code under review* —
those name the attributes a rule reads. The `SEC-*` cards are the evidence; `rules.yaml` is the
catalogue but does not name attributes.

## The work

**1. Change what counts as a consumer.** A captured attribute may name a **rule** — `SEC-091` — as
its consumer, as well as a ledger row. The gate keeps its job: an attribute naming nothing is dead
capture and still fails the build. Mutation-test it in both directions and record which directions
were observed.

**2. Map every attribute to every rule that consumes it**, not to one. This is the
`FIRST-PARTY-VERIFICATION.md` shape and it is chosen for its reverse lookup: the question worth
answering is *"if this attribute is missing or wrong, what breaks?"*, and a single named consumer
cannot answer it. A one-to-one mapping proves only that an attribute is not dead.

**3. Re-derive the catalogue against all sixty-two rules.** For each rule, from its card: what must
capture have read for this rule to be answerable at all? Then take the union. Some will already be
present. Some will be missing. Some rules will turn out to need no attribute beyond
`nTSecurityDescriptor`, and saying so is a result rather than a gap.

**4. Report what the union costs.** An attribute is not free: it is bytes per object across a forest,
and `S-20` measured that parsed entries cost 4.81 GB per 100,000 objects. If the union is much larger
than today's catalogue, that is a finding and possibly a decision for the owner.

**Specific questions this session should answer:**

- **Which rules need an attribute capture does not request?** Named per rule, with the card as
  evidence.
- **Which rules need no attribute at all** beyond the universal set? Per
  `DESIGN-what-makes-a-finding.md` these should mostly be the capability rules, and if they are not,
  that document is wrong and should be corrected.
- **Which captured attributes no rule consumes?** They are either dead, or consumed by presentation
  rather than a rule, and the two must be told apart.
- **Does any rule need something that is not an attribute at all?** SYSVOL file contents and
  certificate template objects are the known cases. The first is B14/B15. The second is already
  served, because the Configuration naming context is captured with `nTSecurityDescriptor` on every
  object — **verify that rather than assume it**, since it was asserted once in conversation from a
  search rather than a reading.
- **What does the product refuse to read?** LAPS password attributes are the live case: capture can
  already tell *withheld* from *absent* by reading `searchFlags` and `systemFlags` per forest, but
  whether to request a password value at all is a different question. Reading one as an administrator
  succeeds and puts a live credential in the evidence bundle. **That is the owner's decision, not the
  session's.**

## Rules

- Product decisions are the owner's. Present them with options and costs, and wait. Engineering
  decisions are yours: decide, then say what it cost. **A brief saying "decide X" is not delegation
  of a product decision.**
- **Say whether a claim was read or searched.** A `git grep` count is not a reading, and this
  repository has repeatedly been misled by treating one as the other — three times in the session
  that produced this brief, including two capture gaps that did not exist. When a claim is
  load-bearing, open the file.
- **Do not type a count into a finding. Write the command that produces it**, next to the number, and
  **run the command as written** — a command that does not reproduce its own number is worse than no
  command. See the finding block in [`docs/review/TEMPLATE.md`](../../review/TEMPLATE.md).
- **State confidence honestly.** *Verified* means read; *suspected* means inferred;
  *needs-environment* means it needs a forest.
- Where a judgement rests on what the old implementation did, read the old implementation.
  [`docs/map/`](../../map/README.md) names the file; it is not the evidence.
- Nothing inherited is definitive, per
  [`0033`](../../decisions/0033-nothing-inherited-is-definitive.md).
- **The rule cards are the intent; the old evaluator code is the approximation.** Several cards mark
  an exclusion *"(Implicit, not enforced by code)"* against an `[IMP-*]` tag. Where the two disagree,
  the card wins for the purpose of deciding what capture must read.
- Records are corrected in place per
  [`0032`](../../decisions/0032-a-decision-record-is-corrected-in-place.md), Context sections
  excepted. `F-S20-13`'s reasoning is challenged by this session's premise; **name it, and let the
  owner decide whether it is edited.**
- `src/SecureAD.*` and `tests/SecureAD.*` are frozen. `next/` is where work happens.
- Scratch files go to `$env:TEMP`, never inside the repository. Do not stage with `git add -A`; name
  the files.
- After any scripted edit, check `git diff --numstat`, because the shell strips a UTF-8 BOM.
- No multi-line here-strings in PowerShell. Write long text to a file and read it.

## Finish by

- Writing `docs/next/S-23-[slug].md` in the [`docs/review/TEMPLATE.md`](../../review/TEMPLATE.md)
  shape, with a status on every finding and a **verified-safe** section that is not empty
- **Answering the five specific questions above**, or saying plainly which could not be answered
- Updating `CapturedAttributeCatalog` and [`S-8`](../S-8-captured-attribute-catalogue.md) together,
  with the consumer column naming rules
- **Recording, per attribute, every rule that consumes it** — not one
- Recording against **B2** the open question of whether a LAPS password value is requested at all,
  and against `F-S20-13` that its reasoning was challenged
- Naming the slice document in [`docs/next/README.md`](../README.md) §`Status`, which
  `RebuildStatusDocumentationTests` requires
- Adding the new documents to `next/SecureAD.Next.sln`
- Appending one entry to [`docs/review/SESSION-LOG.md`](../../review/SESSION-LOG.md), in plain
  language
- Running `dotnet build next/SecureAD.Next.sln` and the full test suite
- **Reading** `git status --porcelain` over the whole repository — reading the list, not counting it
  — and `git diff --numstat` before committing
- Committing, with the message written to a file outside the repository rather than a here-string
