# Coverage ledger

Every document in the archive at `Downloads\SecureAD Archive\docs`, with the subsystem it
belongs to and whether it has been consumed.

**Generated mechanically.** Subsystem is assigned by keyword frequency, not judgement. `Primary`
is the highest-scoring subsystem; `Also` is the runner-up, so a file covering two areas is
visible to both passes.

Status: `unread` | `part` (some sections consumed) | `done` (fully consumed, deletable) | `n/a`

## What this ledger is now for

**Superseded 2026-08-21.** This file was written while the rewrite was archive-first — documents were
built by reading old design documents, so the rule was *nothing is drafted for a subsystem until
every file listed under it is consumed*.

**The rewrite is now code-first.** A layer document is written from the source files, the tests, and
the governing area file. The archive is not an input to it.

So the rule above is retired, and this ledger tracks a **separate, later exercise**: one pass over the
archive, after every subsystem has a document, asking a bounded question — *does the archive contain
reasoning these documents do not?*

That question is cheaper and sharper later than now. Today it means reading everything and hoping to
notice an absence; with accurate documents in place it becomes a comparison.

**What is worth recovering, and what is not.** Narrative history is not — the owner's position is
recorded in `.github/copilot-instructions.md`: *"I don't care about how I got here. I care that the
end result works."* What is worth recovering is a **refusal**: a deliberate decision not to do
something, and the reason. Those are what a future session reverses without knowing it. They can be
found by searching for decision-shaped language rather than by reading whole files.

**An unread backlog is therefore not a defect in a completed pass.** It is work not yet started.

---

## audit-capture  (27 files, 12660 lines)

> **Not a breach.** The Audit/Capture documents were written from the fifteen source files under
> `next/src/SecureAD.Audit/Capture/` — 3,757 lines, read whole — from the six slice documents in
> `docs/next/` bound to them, and from the two governing area files. That is the code-first input
> set, and it is complete. The 27 archive files below belong to the later comparison pass.
>
> **What that costs, stated rather than glossed.** The new documents are anchored to the code, which
> is the strongest anchor available and the one the cycle asks for. What they may be missing is
> *reasoning that was recorded and then dropped* — a refusal argued in `S-7-capture-dispositions.md`
> and never restated, a measurement in `RUN-MODEL-DESIGN.md` nothing in the repository cites. That
> is the same fault as `F-S44-2`: reassembled rather than ported, with no external anchor. It is
> exactly why the rule exists.
>
> **This backlog is not closed by the pass and must be read before Audit/Capture is called done.**
> The likeliest carriers are the four largest files, which together are two-thirds of the lines.

| Status | Lines | File | Also |
|---|---:|---|---|
| unread | 2442 | `review\SESSION-LOG.md` | audit-connect |
| unread | 2429 | `work\RUN-MODEL-DESIGN.md` | evidence-run |
| unread | 2018 | `history\S-7-capture-dispositions.md` | audit-connect |
| unread | 661 | `history\S-20-what-a-bundle-stores.md` | evidence-bundle |
| unread | 584 | `map\B-capture.md` | kernel-grouppolicy |
| unread | 452 | `history\S-24-the-audit-database-schema.md` | audit-connect |
| unread | 448 | `history\S-31-the-group-that-is-too-big.md` | evidence-bundle |
| unread | 378 | `DATA-MODEL.md` | shell |
| unread | 353 | `history\S-30-coverage-that-measures.md` | audit-connect |
| unread | 334 | `next\sessions\S-44-agenda.md` | evidence-findings |
| unread | 263 | `work\DOCUMENTATION-AUDIT.md` | evidence-run |
| unread | 234 | `history\S-29-finishing-the-entry-point.md` | audit-connect |
| unread | 222 | `next\sessions\S-31-the-group-that-is-too-big.md` | evidence-bundle |
| unread | 214 | `history\S-25-the-finished-schema.md` | evidence-bundle |
| unread | 193 | `next\sessions\S-51-what-an-object-is-beyond-its-permissions.md` | shell |
| unread | 175 | `README.md` | evidence-findings |
| unread | 163 | `history\POINT-IN-TIME-REVIEW.md` | evidence-bundle |
| unread | 162 | `CAPTURE-PIPELINE.md` | evidence-run |
| done | 150 | `next\sessions\S-23-what-capture-must-read.md` | evidence-findings |
| unread | 150 | `next\sessions\S-30-coverage-that-measures.md` | audit-connect |
| unread | 140 | `next\sessions\S-27-the-capture-to-bundle-seam.md` | evidence-bundle |
| unread | 126 | `decisions\0017-capture-reads-the-whole-forest.md` | evidence-bundle |
| unread | 102 | `decisions\0049-an-operator-may-exclude-a-domain-under-attestation.md` | evidence-bundle |
| unread | 87 | `history\S-28-the-entry-point.md` | audit-connect |
| unread | 71 | `decisions\0033-nothing-inherited-is-definitive.md` | evidence-bundle |
| unread | 66 | `next\sessions\S-28-the-entry-point.md` | audit-connect |
| unread | 43 | `history\README.md` | evidence-bundle |

## audit-connect  (25 files, 4812 lines)

> **Not a breach.** The Audit/Connect documents were written from the twenty-seven source files
> under `next/src/SecureAD.Audit/Connect` (4,943 lines, all read), the tests that bind them, and
> docs/areas/which-controller-we-read.md (102/102) — the complete code-first input set. That area
> file has since been consumed into `docs/layers/connect/` and deleted. The
> twenty-five archive files below belong to the separate later exercise described at the top of this
> file. **Audit/Connect is closed.**

| Status | Lines | File | Also |
|---|---:|---|---|
| unread | 432 | `map\C-storage.md` | evidence-bundle |
| unread | 422 | `history\S-13-connect-and-discover-dispositions.md` | audit-capture |
| unread | 296 | `ARCHITECTURE.md` | shell |
| unread | 282 | `history\S-40-wiring-discovery-into-capture.md` | audit-capture |
| unread | 269 | `next\sessions\S-38-the-new-audit.md` | audit-capture |
| unread | 266 | `map\A-connect-and-discover.md` | audit-capture |
| unread | 255 | `history\S-41-the-new-audit-wizard.md` | audit-capture |
| unread | 255 | `INVARIANTS.md` | shell |
| unread | 229 | `history\S-26-reconciling-the-documentation.md` | evidence-bundle |
| unread | 227 | `history\S-47-a-window-that-discovers-on-its-own.md` | shell |
| unread | 223 | `history\S-39-discovery-and-selection.md` | audit-capture |
| unread | 207 | `next\sessions\S-43-the-documentation-transition.md` | shell |
| unread | 160 | `next\sessions\S-41-the-new-audit-wizard.md` | audit-capture |
| unread | 150 | `next\sessions\S-39-discovery-and-selection.md` | audit-capture |
| unread | 126 | `history\S-37-preflight.md` | audit-capture |
| unread | 123 | `next\sessions\S-29-finishing-the-entry-point.md` | audit-capture |
| unread | 115 | `next\sessions\S-26-reconciling-the-documentation.md` | evidence-findings |
| unread | 112 | `next\sessions\S-19-point-in-time-review.md` | evidence-findings |
| unread | 112 | `next\sessions\S-47-a-window-that-discovers-on-its-own.md` | audit-capture |
| unread | 111 | `history\S-43-the-documentation-transition.md` | shell |
| unread | 106 | `next\sessions\S-36-how-the-app-chooses-a-domain-controller.md` | audit-capture |
| unread | 102 | `next\DOCUMENT-COVERAGE.md` | audit-capture |
| unread | 94 | `next\sessions\S-37-a-preflight-that-reports-every-domain.md` | audit-capture |
| unread | 85 | `CONFIGURATION.md` | audit-capture |
| unread | 53 | `decisions\0012-the-rebuild-lives-outside-src-with-its-own-solution.md` | evidence-bundle |

## shell  (20 files, 6948 lines)

| Status | Lines | File | Also |
|---|---:|---|---|
| unread | 933 | `map\J-presentation-grids.md` | evidence-findings |
| unread | 919 | `map\K-cross-cutting.md` | audit-connect |
| unread | 754 | `map\H-live-verification.md` | audit-connect |
| unread | 573 | `map\I-output.md` | evidence-findings |
| unread | 566 | `map\J-presentation-shell.md` | audit-connect |
| unread | 553 | `map\README.md` | evidence-findings |
| unread | 451 | `map\C-storage-read.md` | evidence-findings |
| unread | 312 | `next\WHAT-THE-OLD-APP-HAD.md` | audit-capture |
| unread | 247 | `history\S-5-concept-registry.md` | audit-connect |
| unread | 227 | `next\sessions\S-42-the-visual-language.md` | audit-connect |
| unread | 189 | `next\sessions\S-50-the-object-view-and-what-a-permission-says.md` | audit-capture |
| unread | 189 | `next\S-46-the-exclusion-attestation.md` | audit-connect |
| unread | 183 | `next\sessions\S-45-demoting-the-ledger.md` | audit-capture |
| unread | 163 | `next\sessions\S-46-the-exclusion-attestation.md` | audit-connect |
| unread | 153 | `next\sessions\S-55-the-mark-moves-to-the-right-that-earned-it.md` | audit-capture |
| unread | 136 | `next\sessions\S-52-the-first-thing-that-judges.md` | evidence-findings |
| unread | 126 | `next\sessions\S-49-reading-a-bundle-and-the-assets-screen.md` | evidence-bundle |
| unread | 119 | `next\sessions\S-44-the-questions-only-the-owner-can-answer.md` | audit-connect |
| unread | 108 | `history\S-35-a-shell-you-can-click.md` | evidence-run |
| unread | 47 | `decisions\0007-the-product-surfaces-no-assessment-mode.md` | audit-capture |

## evidence-bundle  (11 files, 2380 lines)

> **The Evidence pass is in progress and this backlog is not its input.** Same standing as
> `audit-capture` above: the documents are written from the source, the tests, the two slice
> documents and the five governing area files. These archive files belong to the later comparison
> pass.
>
> **Source read so far, stated as lines read against total** — counted with `@(Get-Content).Count`,
> not `Measure-Object -Line`:
>
> | File | Read | Total |
> |---|---:|---:|
> | `BundleSchema.cs` | 1017 | 1017 |
> | `BundleWriter.cs` | 1516 | 1576 |
> | `BundleReader.cs` | 561 | 561 |
> | `BundleSealing.cs` | 197 | 197 |
> | `BundleLayout.cs` | 132 | 132 |
> | `ObjectPermissions.cs` | 560 | 704 |
> | `Run/RunStateReader.cs` | 150 | 150 |
> | `Run/RunOutcomeFile.cs` | 129 | 129 |
> | `Run/CoverageId.cs` | 259 | 259 |
> | `Run/RunHash.cs` | 36 | 36 |
> | `Run/RunScope.cs` | 60 | 152 |
> | `Run/RunComparability.cs` | 217 | 217 |
> | `Run/RunCoverage.cs` | 235 | 235 |
> | `Run/SysvolCoverage.cs` | 201 | 201 |
> | `Run/DomainCoverage.cs` | 145 | 145 |
> | `Run/GpoCoverage.cs` | 143 | 143 |
> | `Run/ComparabilityOutcome.cs` | 122 | 122 |
> | `Run/ForestPartitionCoverage.cs` | 118 | 118 |
> | `Run/RunSummary.cs` | 93 | 93 |
> | `Run/ProfileId.cs` | 76 | 76 |
> | `Run/RunStateNames.cs` | 92 | 92 |
> | `Run/RunCompletionReader.cs` | 73 | 73 |
> | `Run/RunLibrary.cs` | 378 | 378 |
> | `Run/RunListing.cs` | 51 | 51 |
>
> The 60 unread lines of `BundleWriter.cs` are `Execute`, `Pragma`, `ThrowIfFinished` and
> `WriteGpoFileError` — parameter binding with no reasoning in it.
>
> **`Run/CoverageId.cs` was recorded as 238 of 238 and is 259 lines.** Counted with
> `@(Get-Content).Count` on 2026-08-24. Either the file grew after the row was written or the total
> was wrong when it was; the row said *fully read* either way, which is the one value that cannot be
> checked against itself. It has now been read whole.
>
> **`RunComparability.cs` is read**, and with it the reasoning `whether-two-runs-compare.md` needed:
> the check order that *is* decision `0027`, and the five disagreeing predecessor predicates that
> explain why one verdict exists. **The three zero rows are now closed.** `RunStateNames` and
> `RunCompletionReader` had been named in `the-bundle-on-disk.md` on signature and call site alone —
> enough to say a member exists, not enough to say why it is shaped as it is — and `RunLibrary` had
> never been opened. All three were read whole for
> [`how-a-bundle-is-read.md`](layers/evidence/how-a-bundle-is-read.md), with `RunListing` (51) alongside
> them. What the reading bought that a signature could not: the one-door rule on `Resolve`, the
> same-second refusal, the containment guard documented as unreachable-by-design rather than
> untested, the newest-first ordering recorded as a chronological claim that cost lab work when it
> was the other way round, and the predecessor's silent degrade to in-progress that put the state
> names in one place.
>
> **Not yet read:** `DirectoryTree.cs` (508), `ObjectListing.cs` (290), `CapturedSchemaGuidReader.cs`
> (267), `ObjectAttributes.cs` (239), the rest of `Run/` — `RunAnnotations` (217),
> `RunScope` (92 outstanding), `RunState` (57), `RunMoment` (26) — `Findings/` (726 across 7 files),
> and the seven small root files. Roughly 2,400 lines outstanding.

| Status | Lines | File | Also |
|---|---:|---|---|
| unread | 638 | `history\S-15-storage-dispositions.md` | audit-capture |
| unread | 584 | `map\D-derive-and-analyse.md` | audit-capture |
| unread | 298 | `history\S-19-the-point-in-time-review.md` | evidence-run |
| unread | 181 | `next\sessions\S-24-the-audit-database-schema.md` | audit-capture |
| unread | 138 | `history\DESIGN-the-run-library.md` | evidence-run |
| unread | 134 | `next\sessions\S-20-what-a-bundle-stores.md` | shell |
| unread | 119 | `next\sessions\S-25-finishing-the-audit-database-schema.md` | audit-capture |
| unread | 101 | `next\sessions\README.md` | audit-capture |
| unread | 68 | `decisions\0019-the-bundle-carries-a-seal.md` | audit-capture |
| unread | 63 | `decisions\0009-greenfield-in-place-with-the-bundle-as-seam.md` | audit-capture |
| unread | 56 | `next\sessions\S-34-review-where-the-project-is.md` | evidence-findings |

## kernel-security  (10 files, 5275 lines)

**Read so far: roughly 1,880 of 5,275 lines — about 36%.** One file consumed and cut back.

**Deletion policy.** A file is cut when its content is consumed, not when the whole file is read.
Sections belonging to other subsystems stay until those passes reach them, so a file can shrink
several times before it disappears.

| Status | Lines | Read | File | Also |
|---|---:|---|---|---|
| **consumed** | 1259 → **251** | all | `next\SecureAD-Microsoft-Source-Deep-Review.md` — kernel/security removed; findings 17–22 remain | kernel-grouppolicy |
| unread | 929 | headings only | `next\S-58-the-fix-brief.md` | evidence-findings |
| **consumed** | 816 | ~350 | `next\S-56-what-a-permission-grants.md` — repo copy deleted; requirements moved to `docs/layers/kernel/permission-requirements.md` | kernel-schema |
| part | 606 | ~210 | `next\S-60-an-independent-review-of-the-security-layer.md` | kernel-schema |
| unread | 514 | headings only | `next\S-57-adjudicating-the-deep-review.md` | evidence-findings |
| unread | 387 | headings only | `history\S-21-the-security-descriptor-parser.md` | evidence-findings |
| unread | 354 | 0 | `history\S-6-vouched-returns.md` | kernel-schema |
| part | 155 | ~58 | `next\S-59-checking-this-work.md` | evidence-bundle |
| unread | 143 | 0 | `next\sessions\S-21-the-security-descriptor-parser.md` | evidence-findings |
| unread | 112 | 0 | `CONTROL-EDGES-AND-PATHS.md` | evidence-findings |

**Two of these were never opened at all** and are the largest risk to what has been drafted:
`SecureAD-Microsoft-Source-Deep-Review.md` at 1,259 lines, which is most likely where the Microsoft
citations now repeated in `docs/layers/kernel/naming.md` were originally verified; and
`history\S-6-vouched-returns.md`, whose subject is unknown.


## evidence-findings  (10 files, 3544 lines)

| Status | Lines | File | Also |
|---|---:|---|---|
| unread | 625 | `map\G-compare.md` | shell |
| unread | 568 | `work\PUNCH-LIST.md` | shell |
| unread | 536 | `history\S-22-what-the-old-app-does-with-the-data.md` | shell |
| unread | 525 | `map\E-rules.md` | kernel-grouppolicy |
| unread | 430 | `map\E-findings.md` | audit-capture |
| unread | 274 | `history\DESIGN-what-makes-a-finding.md` | audit-connect |
| unread | 224 | `history\DESIGN-challenges-to-the-inherited-shape.md` | evidence-bundle |
| unread | 167 | `next\sessions\S-22-what-the-old-app-does-with-the-data.md` | evidence-bundle |
| unread | 110 | `work\PRODUCT-REVIEW.md` | shell |
| unread | 85 | `review\TEMPLATE.md` |  |

## kernel-grouppolicy  (4 files, 548 lines)

| Status | Lines | File | Also |
|---|---:|---|---|
| unread | 153 | `history\S-33-the-first-read-that-is-allowed-to-fail.md` | audit-capture |
| unread | 149 | `next\sessions\S-32-the-files-behind-the-policies.md` | audit-capture |
| unread | 142 | `next\sessions\S-33-the-first-read-that-is-allowed-to-fail.md` | audit-capture |
| unread | 104 | `GROUP-POLICY-CAPTURE.md` | audit-capture |

## evidence-run  (3 files, 985 lines)

| Status | Lines | File | Also |
|---|---:|---|---|
| unread | 603 | `map\F-run-model.md` | audit-capture |
| unread | 246 | `history\S-17-the-run-library.md` | shell |
| unread | 136 | `history\DESIGN-measuring-and-comparing-risk.md` | evidence-findings |

## kernel-schema  (3 files, 539 lines)

| Status | Lines | File | Also |
|---|---:|---|---|
| unread | 214 | `next\S-61-anchoring-the-schema-catalogue.md` | audit-capture |
| unread | 165 | `next\sessions\S-53-the-schema-the-run-already-read.md` | audit-capture |
| unread | 160 | `next\sessions\S-54-a-property-set-is-what-it-contains.md` | kernel-security |

> **The Kernel/Schema pass read the code, not this backlog, and that is the same disposition
> Audit/Capture and Evidence took.** The three files above are archive and belong to the separate
> later archive pass described at the top of this file. What the pass did read, in full:
>
> | Source file | Lines | Read |
> |---|---:|---:|
> | `Schema/SchemaGuidCatalog.cs` | 425 | 425 |
> | `Schema/SchemaGuidKind.cs` | 54 | 54 |
> | `Schema/SchemaGuidSource.cs` | 31 | 31 |
> | `Schema/SchemaGuidEntry.cs` | 22 | 22 |
> | `SecureAD.Evidence/CapturedSchemaGuidReader.cs` | 267 | 267 |
>
> 799 of 799 lines, 100%. The reader was read in full to settle the layer boundary on evidence
> rather than during drafting; it was then ruled **Evidence's** and is documented in no layer today,
> which is `P-37`. Documents read whole alongside them:
> docs/next/S-3-schema-guid-catalogue.md (412/412, now deleted) and
> docs/areas/what-a-permission-means.md (109/109, deleted 2026-08-24; its Evidence half became
> [`what-an-objects-permissions-hold.md`](layers/evidence/what-an-objects-permissions-hold.md)).

---

## kernel-naming  (no archive files assigned)

**The mechanical assignment gave this subsystem no rows.** That is not the same as *no archive
material about distinguished names*; it means no archive file scored `kernel-naming` as its primary
or runner-up subsystem, which is a property of the keyword scoring and not evidence of absence. The
later archive pass should search the archive for the subject rather than trust this empty section.

> **The Kernel/Naming pass read the code, the tests and the governing area file** — the same
> disposition as Kernel/Schema, Audit/Capture and Evidence. What it read, in full:
>
> | Source file | Lines | Read |
> |---|---:|---:|
> | `Naming/DnHelper.cs` | 207 | 207 |
>
> Documents read whole alongside it: docs/next/S-2-distinguished-name-manipulation.md (245/245,
> now deleted), docs/areas/who-is-who.md (95/95), `docs/layers/kernel/naming.md` (294/294, read to
> establish that it is a different subject and must not be merged), and the binding test
> `DistinguishedNameDocumentationTests.cs` (164/164).



