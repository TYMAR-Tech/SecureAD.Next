# S-5 — Gate 2, the concept registry

**Type:** slice
**Reviewed at commit:** `HEAD` of `master` at the time of writing
**Size:** 2 new test files, 1 new document, 3 edited documents
**Date:** 2026-08-10

## What it does

Gate 2 makes it a build failure for two types to answer the same question. A **concept** is a
question the product has to answer — *what does this GUID mean?*, *is this permission dangerous?* —
and [`CONCEPT-REGISTRY.md`](../next/CONCEPT-REGISTRY.md) names each one, the single type that owns it, and
the member names that count as answering it. `ConceptRegistryTests` fails the build when any other
type declares a matching member.

A customer never sees this gate. What he would have seen without it is the defect it exists for:
the previous product's live and stored effective-access panels disagreeing about whether the same
permission was dangerous, on two screens built to be read side by side, with nothing to tell him
which was right.

## Shape

- [`docs/next/CONCEPT-REGISTRY.md`](../next/CONCEPT-REGISTRY.md) — seven concepts, in a markdown table
  between `<!-- CONCEPTS:BEGIN -->` and `<!-- CONCEPTS:END -->`.
- `next/tests/SecureAD.Next.Tests/Architecture/ConceptRegistryTests.cs` — the gate, its scanner
  self-test, its exactness tests and its historical-duplicate test. Nineteen cases.
- `next/tests/SecureAD.Next.Tests/Documentation/OwedFindingHomeTests.cs` — unrelated to gate 2,
  folded into the same session: it holds an obligation carried out of a finished component to the
  ledger row that took it.
- `next/tests/SecureAD.Next.Tests/Documentation/ConceptRegistryDocumentationTests.cs` — binds this
  document to the registry and the code, per README §When a document counts as documentation.

No production code changed. Gate 2 adds no types to the rebuild.

## Dependencies

- **Depends on:** `OldAppInventory.RepositoryRoot()` to find `docs/`; the compiled `SecureAD.Kernel`
  assembly, which it reflects over.
- **Depended on by:** every future session, which must add a row when a question gets its first
  owner.
- **Layering violations:** none. The gate lives entirely in the test project.

## The decisions, and what each costs

#### Where the registry lives — markdown, not code

**Chosen:** a markdown table parsed by the test, the shape `SURFACE-REGISTER.md` already proves.

The alternative was a `static readonly` list in the test project. It is type-safe: `nameof` would
make an owning type impossible to misspell, and renaming a type in an IDE would carry the registry
with it.

It was rejected because of who reads this. The owner of this product is an Active Directory
administrator. The registry's most valuable column is the last one — *why it is a concept*, in
sentences — and a list of `nameof` expressions with comments is not a document anybody reads
outside an editor. The registry is the readable record; the test is the enforcement.

**What it costs:** the compiler does not check the owning type name, so a rename can leave the
registry pointing at a type that no longer exists. That cost is paid down by
`EveryOwningTypeExists`, which fails on exactly that, and by `EveryConceptIsAnsweredByTheTypeThatOwnsIt`,
which fails when the members were renamed instead. A second cost is that a markdown table can be
damaged by an editing accident — which happened during this session, and is finding F-S5-1 below.

#### Reflection, not a text scan

**Chosen:** reflection over the compiled production assemblies.

The question gate 2 asks is *which type declares this member*, and a declaration is a fact the
compiler holds. A text scan cannot tell a declaration from a call site, cannot tell either from a
mention in a comment, and would therefore report a duplicate every time one type called another —
which is the correct behaviour it is trying to encourage. This repository has the scar: gate 5's
original wording counted a type "used" because its name appeared inside an XML doc comment.

The precedent runs the other way in `NullDefaultGateTests`, deliberately and for a stated reason:
there the subject is code that must not exist, and reflection can only inspect what compiled.
Different question, different instrument.

**What it costs:** two things, and both are real.

- It sees only .NET. K16's sixth answer to the danger question lived in the rule SQL, and a
  duplicate written in SQL, in a report template or in a configuration file is invisible here.
- It sees only what compiles. A duplicate in a file excluded from the build is missed — which is
  what the seventh guard, the orphan-file check in `GreenfieldGateTests`, exists to make impossible.

Internal and private members are included, which recovers most of the reach a public-only scan
would lose: a second answer hidden behind `private` still has to be kept in step with the first.

#### What counts as a matching member

This is where the gate lives or dies, and it was tested against the two duplicates that motivated
it rather than against intuition.

**Chosen:** each concept lists member-name **globs** — `GuidFor*`, `ByGuid` — matched against the
whole member name. `*` is the only wildcard.

Three things follow from that choice:

- **Anchored, never substring.** `Classify` does not match `CannotClassify`. This is not a
  hypothetical refinement: `PermissionAssessment.CannotClassify` builds the answer the classifier
  has already decided. A substring rule would have fired on the rebuild's own correct code on the
  gate's first run, and a gate that is wrong on day one gets switched off. This repository has made
  the substring mistake before — the S-2 document guard matched a renamed member and let a
  deliberately broken document pass.
- **Verb-shaped, so an answer is distinguished from a name for an answer.** The danger concept
  claims `IsDangerous*` and `Classify*` but not `Dangerous`, because `PermissionVerdict.Dangerous`
  and `PermissionAssessment.Dangerous` name the verdict rather than reaching it. Enum types are
  excluded entirely for the same reason: a vocabulary is not a rival.
- **Wider than what exists today.** A concept that claimed only its owner's current member names
  would catch nothing but a verbatim copy, and the real duplicates were never verbatim copies.

**Tested against the two real duplicates.** K14's `WellKnownGuids` declared `GetGuid`,
`TryGetGuid`, `ByGuid` and `ByLdapName` beside K13's catalogue
(`git grep -n "^\s*public" -- src/SecureAD.Core/Schema/WellKnownGuids.cs`), and K13's `GuidCatalog`
declared `IsDangerous`, one of the six answers K16 replaced. All five names are claimed by the
registry today, asserted by `TheGateWouldHaveCaughtTheDuplicatesThatMotivatedIt`, so a shape
narrowed until it would no longer have caught the original defect fails the build. That is the
evidence for the claim that this gate works, and it is the reason the test exists rather than a
comment saying so.

**What it costs:** a duplicate under a genuinely new name gets through. `ResolveSchemaIdentifier`
answers the schema-lookup question and matches no shape in that row. Nothing mechanical can close
that, which is why every row also states the concept in words — the sentence is what a reviewer
reads, and reviewing is the only thing that catches a new name for an old question.

## Verified-safe

- **The gate has no false positives on the existing kernel.** All seven concepts, matched against
  every declared member of `SecureAD.Kernel`, produce no trespassers — evidence: the first green run
  of `NoTypeOtherThanTheOwnerDeclaresAMemberOfAnOwnedConcept`.
- **`PermissionAssessment.Dangerous` and `CannotClassify` are not reported.** Checked deliberately,
  because they are the nearest miss on the surface today, and asserted as cases in
  `TheShapeMatchesTheWholeNameAndNotAPartOfIt`.
- **No duplicate concept was found inside a row that is already Done.** The five finished rows —
  K13, K14, K15, K16, K17 — hold one owner per concept. The judgement the owner was warned he might
  have to make, about reopening a finished row, does not arise.

## Mutation testing

Six directions were driven, each confirmed to have reached the file before the result was believed.
A seventh attempt is recorded because it did not.

| # | Mutation | Expected | Observed |
|---|---|---|---|
| 1 | Added `MutationProbe.IsDangerous` to `next/src/SecureAD.Kernel/Security/` | The gate fires | Fired, naming the type, the member and the registry line |
| 2 | Owning type changed to `DangerousPermissionClassifierXX` | `EveryOwningTypeExists` fires | Fired, and four other checks with it |
| 3 | Removed `` `ByGuid` `` and `` `ByLdapName` `` from the schema row | The historical-duplicate test fires | Fired on exactly those two cases |
| 4 | Every shape of the `Operation outcome` row broken | `EveryConceptIsAnsweredByTheTypeThatOwnsIt` fires | Fired |
| 5 | `CONCEPTS:BEGIN` renamed | The parse fails loudly rather than emptying | Ten cases failed on the missing marker |
| 6 | A table row truncated to three cells | The parse fails | **Did not fire at first.** See F-S5-1 |
| — | `` `Parse` `` renamed in the security-descriptor row | Nothing; `ParseBase64*` still answers | Passed, correctly. Recorded so the green is not read as a failure to fire |

The two companion guards written in the same session were driven as well.
`OwedFindingHomeTests`: D7's notes stopped naming `F-S4-2`, and the check fired.
`ConceptRegistryDocumentationTests`: the README gate row put back to *to write*, and the false-pass
paragraph removed from this document — each fired on its own case and nothing else.

**One attempt did not reach the file.** A scripted edit targeted the wrong line, `Replace` matched
nothing, and the suite went green — which would have been read as "this direction does not fire" if
the script had not been made to print whether the line actually changed. That is the false pass the
K16 session hit, and the check for it is now habit rather than luck.

## Findings

### F-S5-1 — A malformed registry row was skipped in silence

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `ConceptRegistryTests.RegistryEntries()`, the `cells.Length < 6` branch as first
  written
- **What happens to a user:** nothing directly, and that is the danger. A concept whose row had been
  damaged simply stopped being enforced, and every check went on reporting the registry in perfect
  order. A second dangerous-permission classifier could then have been added without anything
  failing, which ends as two screens disagreeing about the same permission.
- **Why it is this way:** the row-skipping was copied from `SurfaceRegisterTests`, where it exists
  to step over the header and separator rows. It was carried across without asking what else it
  would step over.
- **How it was found:** by mutation testing, and by accident. An editing tool truncated a row while
  a different mutation was being applied, and the suite reported green with a concept missing.
- **Options:** fail on any line between the markers that is neither blank nor a well-formed row
  (chosen); or count the rows and assert the count, which fixes the number in two places and drifts.
- **Test cover:** the parser now asserts on malformed rows, and direction 6 above exercises it.
- **Status:** REPAIRED. Checked 2026-08-10

### F-S5-2 — The registry cannot see a duplicate that is not written in .NET

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `ConceptRegistryTests.Declarations()`, which reflects over
  `typeof(Result<int>).Assembly`
- **What happens to a user:** the same defect the gate exists for, arriving by a route the gate
  does not watch. K16's sixth answer to "is this permission dangerous" was a list inside the rule
  SQL, so this is a route that has already been taken once.
- **Why it is this way:** deliberate. The alternative — a text scan wide enough to read SQL — cannot
  tell a declaration from a mention, which is the failure mode this repository has committed twice
  and the reason gate 2 uses reflection at all.
- **Options:** leave it, and re-examine when the rule catalogue lands, since
  [`0010`](../decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md) already says the
  catalogue is data and the logic is code — which, if held to, means the SQL never holds an answer
  to a concept question in the first place; or add a narrower scan of the rule data at that point.
- **Test cover:** none, and none is possible until there is rule data to scan.
- **Status:** OPEN, accepted for now. Checked 2026-08-10

### F-S5-3 — A concept is only registered if a session remembers to register it

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** there is no check that a newly written type declares a concept, by construction
- **What happens to a user:** a question gets its first owner and no row is written, so the second
  answer six months later fails nothing. The gate protects the seven concepts named; it does not
  discover new ones.
- **Why it is this way:** discovering that a member constitutes a new concept requires knowing what
  question it answers, which is a reading task. Gate 5a has the same shape and says so.
- **Options:** leave it and rely on the session prompt (chosen, and the reason the registry is named
  in README §Gates); or require every public type to be claimed by some concept, which would force a
  concept row for `AceType` and every other vocabulary type and make the file noise.
- **Test cover:** partial. `EveryConceptIsAnsweredByTheTypeThatOwnsIt` catches a concept that has
  decayed; nothing catches a concept never written.
- **Status:** OPEN, accepted by design. Checked 2026-08-10

### F-S5-4 — Shell editing corrupted UTF-8 in a document

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `git diff --numstat -- docs/next/WHAT-THE-OLD-APP-HAD.md` reported ten changed lines after a
  one-line edit; every em dash and section sign in the touched file had been rewritten
- **What happens to a user:** nothing. It is a repository hygiene defect, caught before commit.
- **Why it is this way:** `Get-Content` and `Set-Content` in Windows PowerShell 5 do not round-trip
  UTF-8 without a BOM. `.github/copilot-instructions.md` already warns to check
  `git diff --numstat` after a scripted edit, and that warning is what caught it.
- **Options:** revert and redo through the file editor (chosen); or set `-Encoding utf8NoBOM`, which
  is not available on the shell in use here.
- **Test cover:** none. It is caught by inspecting the diff.
- **Status:** REPAIRED. Checked 2026-08-10

## Open questions for the owner

None. The judgement flagged in advance — whether to reopen a finished row if the new gate found a
duplicate inside one — does not arise, because it found none.

## Not reviewed

- **Gate 4** — no bare counts from public methods. Explicitly out of scope this session and still
  unwritten.
- **Gate 5b** — still blocked on there being something that runs.
- **The old tree.** `src/SecureAD.*` is full of duplicates this gate would fire on. It is frozen and
  being deleted, and pointing a gate at it would produce a list nobody will act on.
