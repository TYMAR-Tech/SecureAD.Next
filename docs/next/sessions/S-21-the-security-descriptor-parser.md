# S-21 — The security descriptor parser, read against the specification

## Scope

This session reviews **the kernel's security descriptor parsing and access control entry
canonicalisation** — ledger rows K13 and K15 — **against Microsoft's published specification**,
rather than against the tests. Work in `next/`, and build and test with `next/SecureAD.Next.sln`.

It reviews. **It does not redesign, and it does not rewrite an oracle.** The output is a slice
document with a finding for each discrepancy, and a repair only where the specification is
unambiguous and the fix is contained. Everything else is written down and raised.

**Why this is worth a session of its own.** The parser is the component every permission finding
rests on. If it misreads a descriptor, the product does not fail — it reports the wrong answer with
full confidence, and the customer acts on it. That is the one thing an audit tool cannot do.

**And the existing tests cannot catch this class of defect.** `GoldenAceHashTests` and the
canonicalisation fixtures were, per §`Tests`, *"computed once and hardcoded"* from the **previous
implementation**, and copied across byte for byte so the rebuild can prove it changed nothing. They
therefore prove **fidelity to the predecessor**, not **correctness**. A misreading inherited from the
old parser passes every test in the tree. The only thing that can find it is reading the
specification.

Out of scope: the dangerous-permission classifier (K16), storage (C1), and anything that consumes a
parsed descriptor. If the review finds those resting on a parser mistake, that is a finding against
this row and a note against theirs.

## Read first

In order:

- [`docs/next/README.md`](../README.md) — §`Tests`, §`Gates`, §`How to continue this work` and
  §`Status`. §`Tests` is the section that governs this session, and the rule that **a golden value
  needing to change is a finding rather than a fix** is the one to have read before touching
  anything
- [`S-1`](../S-1-security-descriptor-parsing.md) — what the parser was built to do and what its
  cases were chosen to cover, and [`S-4`](../S-4-dangerous-permission-classification.md) for the
  consumer that sits closest to it
- [`docs/next/WHAT-THE-OLD-APP-HAD.md`](../WHAT-THE-OLD-APP-HAD.md) — rows K13 and K15, and K16 for the boundary
- [`0033`](../../decisions/0033-nothing-inherited-is-definitive.md) — which is the whole basis for
  this session: the fixtures are inherited, so they are not definitive either
- [`0015`](../../decisions/0015-a-bundle-names-a-pattern-it-never-explains-one-away.md) and
  [`0020`](../../decisions/0020-the-seal-detects-corruption-not-tampering.md) — what downstream
  depends on a stable canonical form and a stable hash
- [`S-20`](../../history/S-20-what-a-bundle-stores.md) — `F-S20-7` and `F-S20-9`, which record two things the
  predecessor's storage discarded and one place where a parse was never performed at all

**The specification, which is the point of the session.** Read these directly rather than any
summary of them:

- `[MS-DTYP]` §2.4.5 `ACL`, §2.4.4 `ACE`, and §2.4.6 `SECURITY_DESCRIPTOR` — the wire format, the
  revision fields, and what each ACE type carries
- `[MS-DTYP]` §2.4.4.1 `ACE_HEADER` — the flags byte, and which bits are inheritance and which are
  audit
- `[MS-ADTS]` §5.1.3 — the ordering rules Active Directory applies to a DACL, and how object-specific
  entries interact with the canonical order
- The `ACCESS_MASK` layout, including the generic rights and how they map onto directory object
  rights

Where the rebuild's parser and the specification differ, **the specification is the evidence and the
code is the claim** — and per [`0033`](../../decisions/0033-nothing-inherited-is-definitive.md) the
old implementation's agreement with the new one proves nothing about either.

## The work

**Read the parser against the format, field by field.** `SecurityDescriptorParser`,
`AceNormalizer`, `AceCanonicalization`, `GenericRightsExpander`, `ParsedAce` and
`ParsedSecurityDescriptor`. For each field: what the specification says it is, what the code reads,
and whether a malformed or unexpected value is refused, recorded, or silently accepted.

**Give particular attention to the cases a lab forest never produces**, because those are the ones
no test and no manual run has ever exercised:

- ACE types the parser does not recognise — callback, conditional and resource-attribute entries
  from Dynamic Access Control. Are they refused, skipped, or counted as something else? A skipped
  entry that grants access is a permission the product will never report
- a descriptor whose declared size disagrees with the bytes present, or whose ACE count disagrees
  with the entries that parse
- the difference between an absent DACL and an empty one, which grant opposite things, and whether
  the control flags are read to tell them apart
- generic rights expansion, and whether the mapping used matches the directory's own
- ordering: whether a non-canonical DACL as the directory actually stores it is normalised without
  changing which entries win

**Say what happens to a customer for each discrepancy**, in the template's terms. A parse difference
that cannot change a reported permission is a note; one that can is a finding with a severity.

**Report what the golden values would become.** Where a fix would change a hardcoded hash or a
fixture, record the old value, the new value, and why the new one is right — and **stop there**. Per
§`Tests` a golden value edited to match new behaviour deletes the evidence and keeps the ceremony.
That is a conversation with the owner, not an edit.

## Rules

- Product decisions are the owner's. Present them with options and costs, and wait. Engineering
  decisions are yours: decide, then say what it cost. **A brief saying "decide X" is not delegation
  of a product decision.**
- **A golden value that needs editing is a finding, not a fix.** See §`Tests`. This session is the
  most likely one yet to want to edit one, which is why it is stated twice.
- Nothing inherited is definitive, per [`0033`](../../decisions/0033-nothing-inherited-is-definitive.md).
  That includes the fixtures, the hashes, and `S-1` itself.
- **Where a decision rests on what the old implementation did, read the old implementation.**
  [`docs/map/`](../../map/README.md) names the file; it is not the evidence.
- **When a decision is made, sweep what it invalidates in the same breath** — every document, ledger
  row, comment and test that repeated the old claim. Not at the end of the session.
- Records are corrected in place per
  [`0032`](../../decisions/0032-a-decision-record-is-corrected-in-place.md), Context sections
  excepted. The test is: *would a grep hit on this line, with no surrounding context, mislead
  someone?*
- Mutation-test every new or changed guard in both directions and record which directions were
  observed. Revert from a baseline held outside the repository, and verify the revert by an anchored
  match rather than a substring.
- Rows in `WHAT-THE-OLD-APP-HAD.md` are replaced whole by
  [`next/tools/Replace-InventoryRow.ps1`](../../../next/tools/Replace-InventoryRow.ps1), never edited in
  part. See `F-S17-6`.
- `src/SecureAD.*` and `tests/SecureAD.*` are frozen.
- Scratch files are written to `$env:TEMP`, never inside the repository. Do not stage with
  `git add -A`; name the files.
- No multi-line here-strings in PowerShell. Write long text to a file and read it.

## Finish by

- Writing `docs/next/S-21-[slug].md` in the [`docs/review/TEMPLATE.md`](../../review/TEMPLATE.md)
  shape, with a status on every finding and a **verified-safe** section that is not empty — a parser
  read against a specification with nothing confirmed correct was not read carefully
- Recording, for any discrepancy found, whether it can change a permission the product reports, and
  saying so in plain language
- Listing every golden value or fixture a proposed fix would change, with old value, new value and
  the specification reference that decides it — **and changing none of them**
- Replacing rows K13 and K15 in [`docs/next/WHAT-THE-OLD-APP-HAD.md`](../WHAT-THE-OLD-APP-HAD.md), and any other row
  this session's findings change
- Adding any new public type to [`SURFACE-REGISTER.md`](../SURFACE-REGISTER.md) and
  [`CONCEPT-REGISTRY.md`](../CONCEPT-REGISTRY.md) where it owns a question
- Naming the slice document in [`docs/next/README.md`](../README.md) §`Status`, which
  `RebuildStatusDocumentationTests` requires
- Adding the new documents to `next/SecureAD.Next.sln` so they appear in Solution Explorer
- Appending one entry to [`docs/review/SESSION-LOG.md`](../../review/SESSION-LOG.md), in plain
  language
- Running `dotnet build next/SecureAD.Next.sln` and the full test suite
- **Reading** `git status --porcelain` over the whole repository — reading the list, not counting it
  — and `git diff --numstat` before committing
- Committing, with the message written to a file outside the repository rather than a here-string
