# S-19 — The point-in-time review

**Type:** sweep
**Reviewed at commit:** `d4fdfdfa`
**Size:** 30 decision records, 69 production files, 8 slice documents
**Date:** 2026-08-12

## What it does

This session produced no code. It read every decision record against every other, and every
load-bearing claim against the code rather than against a document describing the code, and wrote
the result down at [`POINT-IN-TIME-REVIEW.md`](POINT-IN-TIME-REVIEW.md).

It exists because nothing in this repository checked that the decision records agreed with each
other. The gates catch drift between a document and the code it names; they do not catch a decision
that is coherent, well argued, testable and contradicted by another decision in the same folder. On
2026-08-12 that was paid for once, when two records were found resting on a mechanism a third had
removed eight days earlier — found by accident, by a session reading `0017` for a different reason.

If it vanished, the loss would be the one thing it found that no test could: five accepted records
telling a customer the product's evidence is cryptographically signed when it is not.

## Shape

Three passes, in the order the brief set.

- **Every accepted record against every other**, looking for contradiction rather than overlap.
- **Every load-bearing claim against the code**, using `git grep` over `next/`, never `docs/map/` or
  a slice document.
- **Every decision against what is built on it**, asking whether the two still match.

The deliverable is [`POINT-IN-TIME-REVIEW.md`](POINT-IN-TIME-REVIEW.md), bound by
`PointInTimeReviewTests` in `next/tests/SecureAD.Next.Tests/Documentation/`.

## Dependencies

- **Depends on:** `docs/decisions/` (all 30 records), `docs/next/README.md`, `WHAT-THE-OLD-APP-HAD.md`, the
  `S-*` slice documents, and the rebuild tree at `next/src/`.
- **Depended on by:** nothing yet. It is a snapshot, and it starts going out of date immediately.
- **Layering violations:** none — this session added no production code.

## Verified-safe

Checked against the code and found correct. Recorded so they are not re-investigated.

- **The comparability outcomes match `0027`.** `ComparabilityOutcome` has nine members against
  `0027`'s ten situations; states 9 and 10 are both fully comparable and differ only in whether
  anything changed. Evidence at `next/src/SecureAD.Evidence/Run/ComparabilityOutcome.cs:19-65`.
- **The run states match `0028`, and each is reached by observation.** Six members, and
  `RunStateReader.Observe` walks the exact order the record specifies, including the liveness test
  `0029` decided. Evidence at `next/src/SecureAD.Evidence/Run/RunState.cs:25-57` and
  `RunStateReader.cs:51-93`.
- **The surface register is honest about what has no caller.** `RunComparability`, `BundleLayout`
  and the writing half of `RunOutcomeFile` are each recorded against a future row rather than left
  to look finished. Evidence at `docs/next/SURFACE-REGISTER.md:110,129,138`.
- **`0008`'s correction by `0014` is properly surfaced**, on `0008`'s own status line. It is the
  precedent this session followed for the five `signed` records.
- **`0025`, `0026` and `0019` carry supersession markers in both their status lines and the index.**
  The index gap that lost `0025` and `0026` on 2026-08-12 has since been closed.

## Findings

### F-S19-1 — Five accepted records call the bundle *signed*, and it is not

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** `docs/decisions/0003:15,16,38`, `0004:38`, `0009:14`, `0015:41`, `0017:66`, against
  `0020:18-22,58`. Repeated to a customer at `docs/next/S-7-capture-dispositions.md:1560` and
  `docs/next/S-8-captured-attribute-catalogue.md:236`, and in a test failure message at
  `next/tests/SecureAD.Next.Tests/Capture/CredentialAttributeGuardTests.cs:77`.
- **What happens to a user:** an auditor or insurer receives a bundle described as *signed* and
  understands it as proof the artefact came from this product and nobody else. It is not. There is
  no key anywhere in the product, so the seal proves only that the bytes have not changed since it
  was written, and anyone with write access to the folder can rewrite both. `0020` had already
  decided this and called designing around the stronger claim *theatre*.
- **Why it is this way:** `0019` corrected the mechanism on 2026-08-12 and said outright *"It is
  called a seal and not a signature, because it is not one."* `0020` superseded `0019` the next day.
  The vocabulary did not travel with the correction, and `0019` — the one record that stated it in
  a sentence — is the record a reader is told to move past.
- **Options:** withdraw the word; build certificate-based signing; or keep the word with a
  documented limit. Presented to the owner with costs on 2026-08-12.
- **Test cover:** none before this session. `PointInTimeReviewTests` does not catch this class of
  defect and says so in its own remarks — it was found by a person reading thirty documents.
- **Status:** REPAIRED 2026-08-12. The owner chose to withdraw the word.
  [`0030`](../decisions/0030-the-product-produces-sealed-evidence-never-signed.md) records the
  ruling. The correction was first applied as a note on each record's status line; that treatment
  was itself replaced the same day by
  [`0032`](../decisions/0032-a-decision-record-is-corrected-in-place.md), because a note at the top
  of a file is invisible to a reader arriving by `git grep` — which is how these records are most
  often read, and how this very finding was made. Each record's `## Decision` and `## Consequences`
  sections are now corrected in place and each `## Context` keeps its reasoning with the superseded
  claim marked inline. The two slice documents, the test message, and
  `docs/review/00a-product-identity.md` — the sentence all five records inherited the word from —
  are corrected.

### F-S19-2 — `0003`'s decision survives and its stated reason does not

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `docs/decisions/0003:13-18,35`, against `0020` and `0021:31-34`.
- **What happens to a user:** nothing directly. The risk is to the next person to reason from
  `0003`, who would build on an integrity signature that does not exist — the failure `0027` caught
  in `0025` and `0026`.
- **Why it is this way:** `0021` re-derived the refusal on the seal and said so from its own side.
  `0003` never got the return pointer.
- **Options:** a status note, which is what `0008` got when `0014` corrected it; or leave it and
  rely on someone reading `0021` first.
- **Test cover:** `PointInTimeReviewTests.TheStandingColumnAgreesWithEachRecordsOwnStatusLine` now
  fails if a record's status is qualified and the review shows it as plainly accepted, or the
  reverse. It does not detect a record that *should* be qualified and is not.
- **Status:** REPAIRED 2026-08-12. `0003`'s Context keeps the signature reasoning, marked inline as
  superseded, because it is the fossil showing how the error entered; its Consequences are corrected.

### F-S19-3 — `0009` never received the pointer to `0012`

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `docs/decisions/0009:27,50` says the rebuild is built under `src/next/` and builds
  from `SecureAD.sln`; `0012:31-35` moved it to `next/` and `next/SecureAD.Next.sln` and says so
  from its own side. `0009`'s status line named only `0013`, and the index entry named nothing.
- **What happens to a user:** nothing. A session reading `0009` alone opens the wrong solution and
  reads the wrong tree, which `docs/next/README.md` warns about in its second paragraph.
- **Why it is this way:** supersession is recorded by the superseding record, and nothing obliged
  anyone to edit the superseded one. Three of `0009`'s clauses are now overtaken by three different
  records and it pointed at one of them.
- **Options:** correct the Decision in place under
  [`0032`](../decisions/0032-a-decision-record-is-corrected-in-place.md).
- **Test cover:** none, and none is proposed. A test cannot know that a record *ought* to point
  forward; only that where it does, a listing document agrees.
- **Status:** REPAIRED 2026-08-12. **Reading `0009`'s Decision section whole, rather than fixing only
  the location, found four further stale claims** — that the bundle is a two-way contract, that
  `DATA-MODEL.md` specifies it, that the arrangement buys a working product throughout, and that the
  schema cannot be improved until the old projects go. All four were replaced by `0013` on
  2026-08-10 and none had been corrected. This is why the whole section is read rather than the
  known defect fixed, and it is the same lesson `0031` taught with `0007`'s dead mention of *scope*.

### F-S19-4 — `0007` reasons from a mechanism the rebuild does not have

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `docs/decisions/0007:26-28` keeps the assessment mode in the bundle partly because
  *"compare refuses to compare runs whose modes differ."* `git grep -in "assessment"` over `next/`
  and `docs/next/` returns nothing, and `ComparabilityOutcome` — which `0026` makes the single place
  that answer lives — has no member for it.
- **What happens to a user:** nothing today, because nothing runs. If the clause is honoured later,
  a comparison could be refused for a reason outside the closed set, which is the five-disagreeing-
  predicates failure `0026` was written to end. If it is not honoured, an accepted record says the
  product does something it does not.
- **Why it is this way:** `0007` predates `0026` by thirteen days and predates the removal of the
  second capture mode as a live concern. It is the same sequencing error `0027` records: a record
  reasoning from a mechanism another record had already removed.
- **Options:** supersede the clause, on the grounds that a mode which is constant cannot vary
  between runs and so cannot be a comparability outcome; or add a tenth outcome and the fact capture
  would have to record.
- **Test cover:** none. The closed set is bound to `S-18` in both directions, but nothing binds it
  to the records that assert reasons for refusal.
- **Status:** REPAIRED 2026-08-12. The owner ruled that there is no assessment mode, and
  [`0031`](../decisions/0031-there-is-no-assessment-mode.md) supersedes `0007` entirely rather than
  only its clause — both of `0007`'s grounds for keeping the value had gone, not one.

### F-S19-5 — A production comment argues against the decision the file beside it implements

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `next/src/SecureAD.Evidence/BundleLayout.cs:20-24` states *"An interrupted run and a
  running one are indistinguishable from outside, and that is correct… Claiming to tell them apart
  would mean claiming to know something about a process that is not there to be asked."*
  `0029:38-43` decides the opposite, and `RunStateReader.Observe` implements it at
  `RunStateReader.cs:88-93`.
- **What happens to a user:** nothing directly. A session reading that comment concludes the
  liveness test is wrong in principle and may remove it, after which a run still capturing reports
  as interrupted and the run library offers a delete button beside it — which is the exact defect
  `0029` was written to prevent.
- **Why it is this way:** the comment was written at `S-16` on 2026-08-12; `0029` was decided on
  2026-08-12. The comment was true when written.
- **Options:** correct the remark. It is three sentences and touches no behaviour.
- **Test cover:** none, and none is possible — no test reads prose for agreement with a decision.
- **Status:** REPAIRED 2026-08-12. The paragraph now describes what the presence of each file says
  about a run, names the liveness test, and records that it previously argued the opposite so a
  reader is not left wondering which was meant.

### F-S19-6 — A bundle's file names have two owners

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `BundleLayout.cs:34,41,44,58` names four files; `RunOutcomeFile.cs:51` names the
  fifth. `docs/next/CONCEPT-REGISTRY.md` has no entry for bundle file naming, so gate 2 cannot see
  the split. `0025:10` also describes a bundle as *the evidence file and its seal*, which omits two.
- **What happens to a user:** nothing today. The pattern is the one gate 2 exists to stop, and the
  cost is measured in this repository already — three near-identical ways to ask one question about
  distinguished names, which `0025` cites as how that happened.
- **Why it is this way:** `RunOutcomeFile` was added at `S-18`, two days after `BundleLayout`, and
  the constant went where the reader and writer were rather than where the other names live.
- **Options:** move the constant to `BundleLayout` and add a concept-registry entry so the gate
  holds it; or leave it and accept a second home. The first is cheap now and gets more expensive
  with each consumer, which is the shape of decision `docs/next/README.md` says to raise early.
- **Test cover:** `ConceptRegistryTests` would hold this if the registry had an entry. It does not.
- **Status:** REPAIRED 2026-08-12. `OutcomeFileName` and `OutcomePath` moved to `BundleLayout`;
  `RunOutcomeFile.FileName` and `PathIn` are gone and it calls `BundleLayout` for the path. The
  registry gained a *What a bundle's files are called* row owned by `BundleLayout`, and the guard
  was mutation-tested in both directions: a rival `OutcomeFileName` declared on `RunOutcomeFile`
  failed the build naming the type, the concept and the registry line, and the suite is green with
  it removed. **One claim in this finding was wrong and is withdrawn:** `0029`'s *four files* is
  correct, because the partial and the finished evidence are one file renamed, so `0025` and `0029`
  never disagreed. `0025` was merely incomplete and is corrected.

### F-S19-7 — Scratch files inside the repository

- **Severity:** cosmetic
- **Confidence:** verified
- **Evidence:** `docs/decisions/.tmp-marker` was tracked, empty, and committed by `41e1e956` — the
  commit that recorded the owed review. `next/tools/m.txt`, `next/tools/msg.txt` and
  `next/tools/readme-section.md` are untracked, not ignored, and would be swept up by `git add -A`.
- **What happens to a user:** nothing. It is the mechanism by which four files were committed by
  accident on 2026-08-12, which the session brief names as a rule.
- **Why it is this way:** the practice of writing commit messages to a file, per the repository
  instruction against multi-line here-strings, without the file being outside the repository.
- **Options:** delete the tracked one, which is done; the untracked three belong to another session
  and are left. A `.gitignore` entry for `next/tools/*.txt` would prevent recurrence, but it would
  also hide the next one, which is worse.
- **Test cover:** none.
- **Status:** PARTLY REPAIRED 2026-08-12. `.tmp-marker` removed; the three untracked files left in
  place and named here.

### F-S19-8 — Two defects in this session's own method, both caught

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** recorded live during step 8 of this session.
- **What happens to a user:** nothing, but both are worth writing down because both are the failure
  this repository names first.
  - **A revert check that passed while measuring nothing.** After deleting `0022`'s row to
    mutation-test the guard, the restore was verified by searching the file for the string `0022`,
    which also appears in the document's prose. It reported success while the row was still
    deleted, and the file was untracked so `git checkout` could not have restored it either. Found
    by re-checking with an anchored `^\| 0022 \|` match, and fixed by taking a baseline copy in
    `$env:TEMP` and comparing against it.
  - **A stale binary reported as a test result.** Restoring a mutated test file with `Copy-Item`
    preserved the backup's older timestamp, so MSBuild judged the build up to date and ran the
    mutated assembly. Three consecutive runs reported a failure that was no longer in the source.
- **Why it is this way:** both are the same mistake in different clothes — trusting a check without
  asking what it would have done if the thing it measures were absent.
- **Options:** none needed; both are method, not code.
- **Test cover:** not applicable.
- **Status:** REPAIRED 2026-08-12, within the session.

### F-S19-9 — A supersession marker condemns a whole record when only part of it changed

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `0019` was marked *Superseded by 0020*. `0020` replaced only the tamper framing —
  its own header says so. Everything else `0019` decided remained true, and two things sat behind
  the marker with no live record naming them: the partial-file rename mechanism, restated by `0029`
  four days later, and the sentence *"It is called a seal and not a signature, because it is not
  one"*.
- **What happens to a user:** indirectly, the most expensive thing in this review. That second
  sentence is the exact statement that would have caught `F-S19-1`. It was written on 2026-08-12,
  four days before a cross-reading found five records still describing a bundle as signed to an
  audience of auditors and insurers. It was never hidden — it was behind a marker that told every
  reader the record was finished with.
- **Why it is this way:** the folder offered one supersession marker and no way to say *partly*. A
  session correcting one clause had to choose between marking a whole record dead and leaving it
  looking wholly current, and both are wrong.
- **Options:** require a marker to name where each part of the record went; or forbid supersession
  of a partly-live record entirely.
- **Test cover:** none, and none is proposed. Whether a marker fairly accounts for a record's
  contents is a reading judgement, on the same footing as whether a record is any good.
- **Status:** REPAIRED 2026-08-12. `0032` had already removed the cause by restricting supersession
  to records that are wholly replaced. It gained a further clause requiring a marker to say where
  each part went, and `0019`'s and `0007`'s markers and index entries now do — `0019`'s names `0020`,
  `0029` and `0030` and states plainly that nothing it decided was lost. `0019` also carried a
  consequence claiming its gate is *what lets re-analysis be removed*, which
  [`0021`](../decisions/0021-re-analysis-produces-a-new-bundle.md) reversed the following day; that
  is corrected.

## What is not settled

**Every finding in this document is closed.** All nine were repaired on 2026-08-12, seven of them
after the review itself, in a working session where each was decided and swept in the same breath
rather than recorded and deferred. That order was the owner's instruction and it is the thing this
review most wants remembered: every defect it found existed because a decision was made and what it
invalidated was left standing.

What that produced, beyond the repairs: `0030` withdrawing *signed*, `0031` removing the assessment
mode, `0032` replacing the append-only rule, and `0033` recording that nothing inherited is
definitive.

- **Whether this review is repeated** is a judgement about how fast the records are changing.
  Nothing schedules it, and this document does not propose that anything should. What it does say is
  that no test would have found the defect that mattered — `PointInTimeReviewTests` holds this
  document to the records and cannot notice that two records contradict each other. If it is worth
  having again, it is worth having as a session.
- **Two records were wrong within hours of being written**, `0030` and `0032`, and neither through
  carelessness — the ground moved beneath them. A gap of hours was enough, which is the strongest
  available argument for the same-breath sweep.
- **`next/tools/m.txt`, `msg.txt` and `readme-section.md`** remain untracked inside the repository,
  named in `F-S19-7` and left for the session that put them there.
