# S-26 — Reconciling the documentation with what was built

**Type:** slice
**Reviewed at commit:** `HEAD` of `explore/design-challenges`
**Size:** 8 decision records, 12 documents and the 256-row ledger read against the code; 6 bindings
written, no production code changed
**Date:** 2026-08-13

## What it does

This session makes the tree's documents agree with the code and with the decisions that govern
them, and leaves the parts that describe live code bound by a test.

It is `F-S25-5`. Five documents were caught disagreeing with the code during `S-25` alone, every one
of them by a binding firing. That is the mechanism working, and it is also the whole of its reach:
only bound documents are covered, and [`F-S24-2`](S-24-the-audit-database-schema.md) already proved
a binding cannot detect that a document and the code agree with each other while both describe a
design that was superseded.

**Six disagreements were found. Five were the document; one was the ledger.** None was the code.

## Shape

Five things were owed, and the order mattered — the decision records first, because a record that is
half live and half withdrawn is the shape a slice inherits a dead claim from.

1. **The eight `Accepted`-with-a-correction records** — `0003`, `0004`, `0008`, `0009`, `0015`,
   `0017`, `0025`, `0026` — read against every document citing them. This produced `F-S26-1`, which
   is `F-S24-2`'s shape caught one step earlier.
2. **The six unbound slice documents.** `S-17` first. `S-19` turned out to be unbound in a way the
   file listing hides: `PointInTimeReviewTests` binds `POINT-IN-TIME-REVIEW.md`, which is a
   different document.
3. **Every ledger row's status.** All 256 read; one row cited a binding that has never existed.
4. **`ARCHITECTURE.md`, `READING-ORDER.md` and the four `DESIGN-` notes.** Two `DESIGN-` notes
   claimed nothing in them was built while the code they describe was built, bound and `Done`.
5. **A binding for every document describing live code and having none.** Six were written.

## Verified-safe

Things checked against the code and found correct, recorded so they are not re-investigated.

- **The `signed`/`sealed` correction travelled completely.** Every surviving use of *signed* in
  `docs/next/` is either LDAP connection signing — a real and unrelated mechanism — or a quotation
  of the map's own wording with the corrected position stated beside it. `0030` is cited by all five
  records `F-S19-1` caught, and that is now bound.
- **`READING-ORDER.md` is accurate.** All fourteen source files it names resolve under `next/src/`.
  It was simply unbound.
- **`S-16-the-bundle.md` names every one of the eleven tables `BundleSchema` creates**, and is bound
  by `BundleDocumentationTests`. This was checked because a first draft of this session's historical
  record binding held `S-24` and `S-25` to that list instead and failed on four tables — see
  `What was got wrong`.
- **`ProfileId` and `CoverageId` carry no exclusion or attestation machinery**, by reflection over
  every declared member including non-public ones.
- **The four `DESIGN-` notes all state a status.** Two were stale, none was silent.

## Findings

### F-S26-1 — `S-17`'s retraction stopped one bullet short, and the live half contradicts the code

- **Severity:** breaks-the-next-session
- **Confidence:** verified
- **Evidence:** `docs/next/S-17-the-run-library.md` — the `CoverageId` bullet under `Shape`, the
  `Depends on` entry under `Dependencies`, and two bullets under `Verified-safe` — against
  `next/src/SecureAD.Evidence/Run/CoverageId.cs:30-35` and
  `CoverageIdTests.NothingCarriesExclusionsAnyMore`.
- **What happens to a user:** nothing directly. What happens to the next session is that it reads
  `CoverageId` is a hash of the declared domain set plus the applied OU exclusions, reads **OU
  exclusions are part of the coverage identity** listed as a fact checked against the code, and
  builds on both. The rebuild's `CoverageId` hashes the declared domains and nothing else, says so
  on the type, and has a test asserting by reflection that no exclusion member has returned.
- **Why it is this way:** `S-18` retracted the attestation ladder from this document on 2026-08-12
  and marked two paragraphs. The exclusion claim appears in three other places, and a retraction
  written as prose has no way to say *and everything downstream of this*. The document then went
  unread for four days because nothing bound it — which is the same reason `F-S19-1` gives for how
  five records went on calling the bundle *signed*.
- **Test cover:** none before this session. `RunLibraryDocumentationTests` now binds all five
  withdrawals against the absence of the machinery in the code.
- **Status:** REPAIRED 2026-08-13. The retraction is widened rather than the claims deleted, per
  [`0032`](../decisions/0032-a-decision-record-is-corrected-in-place.md). **The document was wrong
  and the code was right.**

### F-S26-2 — `0034` is Accepted and no ledger row owns it

- **Severity:** breaks-the-next-session
- **Confidence:** verified
- **Evidence:** `docs/decisions/0034-capture-excludes-a-shipped-noise-list.md` is `Status: Accepted`,
  dated 2026-08-13. Across `docs/next/` it is named only at `POINT-IN-TIME-REVIEW.md:95`, and by no
  row of `WHAT-THE-OLD-APP-HAD.md`.
- **What happens to a user:** a decision the product has taken has nobody to carry it out. `0034`
  requires a shipped noise list in the catalogue, a rule that a class may be on it only if it can be
  neither a hop nor a principal, and a test holding that rule. The ledger is the document a session
  opens to find what it owes, so work with no row is work that does not get done — and the cost it
  answers is two thirds of every object in one production forest.
- **Status:** REPAIRED 2026-08-13, recorded against `B3`, the row that owned the exclusion filter
  `0034` replaces. The list itself is owed by `B2`, which owns the catalogue. **No disposition was
  changed and no row was created**, because a row is owed to a map component and `0034` is not one.

### F-S26-3 — `B3`'s note is contradicted by the decision that replaced it

- **Severity:** cosmetic-but-misleading
- **Confidence:** verified
- **Evidence:** `WHAT-THE-OLD-APP-HAD.md`, row `B3`: *capture reads the whole forest, so there is no
  capture-side exclusion to rebuild*, against `0034`.
- **What happens to a user:** a session reading `B3` concludes capture has no exclusion to build.
  It has one — a shipped noise list. What stays deleted is the *operator-configurable* filter, which
  is what the row was ever about, and the note collapsed the two.
- **Status:** REPAIRED 2026-08-13, in the same amendment as `F-S26-2`.

### F-S26-4 — `S-20` states a ledger status that stopped being true three days later

- **Severity:** breaks-the-next-session
- **Confidence:** verified
- **Evidence:** `docs/next/S-20-what-a-bundle-stores.md`, the opening block: *Ledger row C1 is
  unchanged and still reads `Decided, rebuilding after review`.* `C1` reads `Done`, taken there by
  `S-25` on 2026-08-13.
- **What happens to a user:** a reader is told the schema is unbuilt. `C1` is the row everything
  downstream of capture waits on, so believing it is unbuilt is believing the product has no read
  side to build against.
- **Status:** CROSS-REFERENCED 2026-08-13, **not corrected**. `S-20` is a historical record and its
  account of what was found is evidence; `S-24`'s own rule is that a withdrawn finding shows how an
  error entered. The sentence stands and a cross-reference stands beside it. This is the one place
  in this session where the right repair was explicitly not to fix the sentence.

### F-S26-5 — Two `DESIGN-` notes say nothing in them is built, and the code is built and bound

- **Severity:** breaks-the-next-session
- **Confidence:** verified
- **Evidence:** `DESIGN-measuring-and-comparing-risk.md` — *nothing here is built, and no test binds
  it* — and `DESIGN-the-run-library.md` — *nothing here is built yet and no test binds it* — against
  `RunSummary`, `RunCoverage`, `ComparabilityOutcome` and `RunComparability` in
  `SecureAD.Evidence`, ledger rows `F1`, `F2`, `F3`, `F9`, `F10` reading `Done`, and
  `RunComparabilityDocumentationTests`.
- **What happens to a user:** the next session designs something that exists. A status line saying
  *nothing here is built* is an invitation to start, and these two notes cover the run summary and
  the comparison verdict, which are built, bound and closed.
- **Why it is this way:** the notes were honest when written — that is the README's rule working, an
  unbound document visible because it says so. `S-18` built from them and did not come back to the
  header.
- **Status:** REPAIRED 2026-08-13. Headers corrected, bodies left as written, because the reasoning
  below each header is what the built code was built from and still explains it. `F17` — *rule
  built, no door calls it* — and the baseline remain genuinely unbuilt, and both notes now say which
  half is which.

### F-S26-6 — `S-21` was never run and nothing recorded it

- **Severity:** breaks-the-next-session
- **Confidence:** verified
- **Evidence:** `docs/next/sessions/S-21-the-security-descriptor-parser.md` exists; there is no
  `S-21` slice document; `S-21` is referenced nowhere in `docs/next/` except by itself and by this
  session's prompt. It was committed alongside the `S-20` work.
- **What happens to a user:** the review that has the best chance of catching a wrong permission
  verdict is not on anybody's list. `S-21` reads the parser against Microsoft's published
  specification, and its own scope explains why nothing else can stand in for it: `GoldenAceHashTests`
  and the canonicalisation fixtures were computed from the predecessor and copied byte for byte, so
  they prove **fidelity**, not **correctness**. A misreading inherited from the old parser passes
  every test in the tree. Rows `K13` and `K15` read `Done` and are bound, which is precisely why
  nothing suggests anything is owed.
- **Status:** REPAIRED 2026-08-13 as to visibility only. A register of unrun prompts is added to
  `docs/next/sessions/README.md` and bound by `SessionCompletionTests`. **No disposition changed and
  the row is not reopened**; this session changes no dispositions.

## Bindings written

Six, each mutation-tested in both directions with the directions observed recorded below.

| Binding | Document | Document broken → | Code broken → |
|---|---|---|---|
| `RunLibraryDocumentationTests` | `S-17` | withdrawal deleted, **fails** | `AppliedExclusions` added to `CoverageId`, **fails** |
| `DecisionRecordRepairDocumentationTests` | `S-19` | — | `0009` loses its `0012` pointer, **fails**; `BundleLayout` renames the outcome file, **fails** |
| `HistoricalRecordDocumentationTests` | `S-20`, `S-16` | cross-reference reworded, **fails**; table name dropped, **fails** | `BundleSchema` renames a table, **fails** |
| `GoverningDocumentTests` | `READING-ORDER`, `DESIGN-*` | file path moved, **fails**; correction reworded, **fails** | see below |
| `InventoryCitationTests` | `WHAT-THE-OLD-APP-HAD` | phantom citation restored, **fails** | — |
| `SessionCompletionTests` | `sessions/README` | register entry removed, **fails** | — |

**One mutation was unreachable and is recorded rather than claimed.**
`GoverningDocumentTests.TheComparisonAndSummaryTheCorrectionsPointAtExist` asserts that
`RunSummary` and three sibling types exist. Removing `RunSummary` does not fail the test — it fails
the compilation of `SecureAD.Evidence`, because `RunComparability` depends on it. The compiler is
the stronger guard there and the assertion is kept as documentation of why the correction in
`F-S26-5` is safe, not as the thing preventing its reversal.

## What was got wrong

Two of this session's own errors, both caught by its own bindings within minutes of writing them.

**The historical record binding was written against the wrong documents.** Its first draft required
`S-24` and `S-25` to name every table `BundleSchema` creates, and it failed on `partition_coverage`,
`continuation_reference`, `unreadable_security_descriptor` and `captured_object`. The tree was
right. `S-16-the-bundle.md` names all eleven and is bound; `S-24` and `S-25` record two build
sessions and do not owe a complete list of what exists now. Holding a historical record to that
would force it to be rewritten whenever the schema grew, which is the one thing a historical record
may not be. Retargeted at `S-16`.

**Row `A1` was "corrected" from something true to something false.** The sweep in item 3 matched
ledger citations against test **file** names, so `DirectoryCredentialTests` looked missing and was
replaced with `ConnectionSecurityTests`. It is not missing: it is a class at
`ConnectionSecurityTests.cs:373`. `InventoryCitationTests`, written minutes later against **class**
declarations rather than file names, failed on the replacement and the edit was reverted. The row
was right all along. This is worth recording because the failure mode is the session's own subject
seen from the inside — a check that agreed with itself and not with the tree.

**A third, mechanical:** two edits to long single-line table rows in `WHAT-THE-OLD-APP-HAD.md` split them
across lines and dropped rows `A1` and `B3` out of the ledger entirely, which
`InventoryCompletenessTests` caught immediately. The file was restored and the edits reapplied at
line level.

## Not done, and why

- **The capture-to-bundle seam** — `B9`, `B10`, `C15` — is the next building session and was not
  started.
- **No production behaviour changed.** No code file under `next/src/` was modified. Every
  disagreement found was the document or the ledger, so the question of handing one to a row did not
  arise.
- **No ledger disposition changed.** `F-S26-2` and `F-S26-6` both name work that is owed; both are
  recorded against rows that already exist rather than creating rows or reopening `Done` ones.
- **`ARCHITECTURE.md` is unbound still.** Its claims are about which project may use which, which is
  already enforced mechanically by the architecture tests rather than by a document check, so a
  binding would duplicate a stronger guard. Recorded here rather than built.

## What is not settled

**Whether a binding can be written for the failure that started all this.** `F-S24-2` was two
governing documents describing different schemas, agreeing with the code and with each other, and
both wrong. Everything in this session that caught something caught it because the document and the
code disagreed. `F-S26-1` was found by reading the decision first — by a person, in the order the
prompt insisted on — and no test in this repository would have found it. The prompt is right that
the reach of binding is limited, and this session did not widen it. It only made the limit visible
in more places.
