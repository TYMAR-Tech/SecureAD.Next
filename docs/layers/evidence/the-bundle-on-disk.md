# The bundle on disk

**Code:** `next/src/SecureAD.Evidence/BundleLayout.cs`, `BundleSealing.cs`, `Run/RunStateReader.cs`
**Layer:** Evidence — the files a bundle is made of, and what their presence proves.

[`what-a-bundle-holds.md`](what-a-bundle-holds.md) describes what is inside the evidence database.
This page is one level out: which files sit in a bundle directory, what stops a half-written one
being read as a whole one, what the seal proves and what it does not, and how a run's state is read
back off the disk.

Bound by `BundleOnDiskDocumentationTests`, which compares the file table below against the names
`BundleLayout` declares in both directions, the seal table against `SealState` in both directions,
and the state table against `RunState` in both directions. A name in the code and not here fails the
build, and so does a name here and not in the code.

---

## What a bundle is on disk

A bundle is **one directory**, and where it lives is an argument the operator supplies. Nothing
picks a location on the operator's behalf, because a tool that decides for itself where several
gigabytes of evidence go is a tool that fills the wrong disk.

<!-- FILES:BEGIN -->

| Constant | File | What it is |
|---|---|---|
| `EvidenceFileName` | `evidence.db` | The evidence. Present only on a bundle that finished |
| `PartialFileName` | `evidence.db.partial` | A run that has not finished, or did not |
| `SealFileName` | `evidence.db.seal` | The seal covering `evidence.db` |
| `AnnotationsFileName` | `annotations.db` | The customer's notes, acceptances and declared scope. Created at seal time |
| `OutcomeFileName` | `run-outcome.json` | The note a run leaves when it ends badly, saying which ending it was |
| `PreflightFileName` | `preflight.json` | What preflight proved about each domain before any capture traffic was sent |

<!-- FILES:END -->

`BundleLayout` also carries one path helper per file — `EvidencePath`, `PartialPath`, `SealPath`,
`AnnotationsPath`, `OutcomePath` and `PreflightPath` — so that no caller composes a bundle path by
concatenation and no bundle's file names have a second owner.

> `S-16` said a bundle was four files. It was written before `run-outcome.json` and `preflight.json`
> existed and was never revisited, and the count survived because nothing counted it.

**Two of the six sit outside the seal, and have to.** `run-outcome.json` and `preflight.json` are
written by runs that have no `evidence.db` for a seal to cover — a failed run writes the first, and
the second exists before the evidence database does. That is what makes them useful: they survive
the unattended run that died at three in the morning, which is the case where an operator has
nothing else to read. It is also what makes them **not evidence**, and nothing that reads either may
present it as proof of anything.

**`annotations.db` is separate for the opposite reason.** An acceptance written into the evidence
would invalidate the seal that proves the evidence is unmodified, so a customer could not annotate a
bundle without destroying its own proof. Keeping annotations outside is what makes
[`0067`](../../decisions/0067-an-acceptance-names-one-finding.md) and
[`0052`](../../decisions/0052-the-domain-is-the-only-unit-of-scope.md) enforceable rather than
promised. It is created when the bundle is sealed, so that opening a bundle never writes to it.

> `BundleLayout`'s own remarks cite `0015` here. `0015` is *a bundle names a pattern it never
> explains one away* and says nothing about acceptances; the record that governs them is `0067`.

## The name is the mechanism

A run writes `evidence.db.partial`. Renaming it to `evidence.db` is the last act, after the
write-ahead log is folded back in and after the seal is written. A reader opens `evidence.db`, so a
run that was interrupted has no file by that name to offer it.

This is the answer to *what stops a half-written bundle being opened and read as a whole one*, and
it is deliberately not a check. A check has to be remembered at every place a bundle is opened. A
name has to be remembered nowhere: the partial file is not called the thing readers ask for, and
that is true whether or not anybody thought about it.

**A failed run's `.partial` file is left where it is.** Nothing deletes it. Reclaiming disk on a
failure path destroys the only record of how far the run got, on a judgement made by the code that
has just failed, and the file has no name any reader asks for — so leaving it costs disk and never a
wrong answer. Deleting a failed run is the run library's decision and an operator's to be told
about, not the failing code's.

**Why more than one file at all.** Write-ahead logging keeps recent changes in a `-wal` file beside
the database until a checkpoint folds them back
([copying a database](https://learn.microsoft.com/dotnet/maui/data-cloud/database-sqlite#advanced-configuration)),
so during a run the evidence is genuinely spread across several files and cannot be treated as one.
Write-ahead logging is on because it is what the provider's guidance points to for throughput:
SQLite has no asynchronous I/O, and the async methods run synchronously
([async limitations](https://learn.microsoft.com/dotnet/standard/data/sqlite/async)). That is also
why every method on the writer is synchronous. An `async` surface here would await nothing and
mislead every caller about what it costs.

## The seal

The reasoning is [`0020`](../../decisions/0020-the-seal-detects-corruption-not-tampering.md) and
[`0030`](../../decisions/0030-the-product-produces-sealed-evidence-never-signed.md). What matters at
the point of use:

> `S-16` cited `0019` for this. `0019` was superseded on the day it was written and is archived; its
> own header records that nothing it decided was lost, and names where each part went — what the seal
> proves and the four outcomes to `0020`, the rename mechanism and the failed run keeping its
> `.partial` to `0029`, and seal-not-signature to `0030`. All three are cited on this page, so the
> citation went stale by supersession rather than by being wrong.

**What it proves.** The bytes of `evidence.db` are the bytes that were there when the run declared
itself finished. `BundleSealing.Seal` writes `BundleSealContents`, which carries
`BundleSealContents.Algorithm` and `BundleSealContents.Hash` — the algorithm named rather than
assumed, so a later build reading an older seal is not guessing. `BundleSealing.Algorithm` is the
one this product writes, and `BundleSealing.HashFile` is the only way either side computes it.

**What it does not prove.** It is not a signature and is deliberately not called one — there is no
key anywhere in this product, so anyone who can rewrite the evidence file can rewrite the seal
beside it. It catches corruption, truncation and casual editing, and not a determined party. It says
nothing about whether the capture was **complete**: that is a claim the bundle makes in its own
`bundle` and `partition_coverage` tables, and the seal only proves the claim has not been edited
since it was made. And it says nothing about whether the capture was correct.

**`BundleSealing.Verify` has four outcomes**, and only the first opens a bundle.

<!-- SEAL:BEGIN -->

| Outcome | What was observed |
|---|---|
| `Intact` | The seal is present, readable, and matches |
| `Absent` | There is no seal file. Unreachable for a bundle this product wrote, because sealing precedes the rename — so it means the directory was assembled by hand |
| `Unreadable` | A seal file exists and cannot be read. **Not** the same as `Absent`: the one thing that certainly happened is that something happened to the seal |
| `Mismatch` | The seal was read and the file does not match it |

<!-- SEAL:END -->

Folding `Unreadable` into `Absent` would render a failure as a benign absence, which is the one
shape of defect an audit tool cannot have. The implementation being replaced did exactly that.

`SealVerdict` carries `SealVerdict.State`, `SealVerdict.Detail` — never empty, including for
`Intact`, so a caller rendering the detail never renders a blank — and `SealVerdict.MayBeOpened`,
which is the single statement of which states may be opened. Stated once rather than left to each
caller, because a rule spelled out at thirty call sites is a rule that is wrong at one of them.

**A seal present with no evidence file is `Mismatch`, not `Absent`.** The seal was found and the
thing it covers was not, which is a disagreement about the bundle rather than a bundle nobody
sealed.

There is no cached verdict. Reopening a large bundle re-hashes it every time, which costs real
seconds on a bundle of some gigabytes. That cost is accepted, because a cache whose function is to
avoid performing an integrity check is a way for the check to silently never run.

## What became of the run

`RunState` is the one vocabulary for what became of a run, decided in
[`0028`](../../decisions/0028-one-run-state-vocabulary.md), and every one of its six words is arrived
at from something observed on disk rather than assumed. `RunStateReader.Observe` follows the
procedure and returns a `RunStateObservation` carrying `RunStateObservation.State`,
`RunStateObservation.Detail` and `RunStateObservation.RecordedUtc`.

**The table is read top to bottom and the order is the decision, not an implementation choice.**

<!-- STATES:BEGIN -->

| State | Meaning | How it is observed |
|---|---|---|
| Sealed | The audit finished and its evidence is intact | The evidence file is present and its seal verifies |
| Damaged | The evidence is there and cannot be trusted | The evidence file is present and the seal is absent, unreadable or does not match |
| Failed | The audit ended in an error it recorded | No evidence file, and the run outcome file records a failure |
| Cancelled | The operator stopped the audit | No evidence file, and the run outcome file records a cancellation |
| InProgress | The audit is running now | No evidence file, no outcome file, and something holds the partial file open |
| Interrupted | The audit stopped without recording why | No evidence file, no outcome file, and nothing holds the partial file |

<!-- STATES:END -->

**A finished bundle outranks everything**, so a stale outcome file left beside good evidence cannot
make a successful run look like a failed one. **A recorded outcome outranks the liveness test**,
because a run that said why it stopped has told us more than the file system can.

**A crashed run and a running one are told apart, and the file system is what answers.** Both
present a `.partial` file and no `evidence.db`, so the files alone cannot say — but per
[`0029`](../../decisions/0029-a-run-that-ends-badly-says-so.md) the question is whether anything still
holds the partial file open. Nothing does once the writing process ends, whatever ended it, because
the operating system releases handles when a process dies. A recorded heartbeat or a process
identifier would need cleaning up after a crash, which is precisely the moment nothing is running to
clean it. The check opens the file for reading with no sharing and closes it again; it never writes,
because opening a bundle must not alter it.

**A file that cannot be opened for some other reason is not reported as a live run.** A permission
fault on the partial file returns *not being written*, because the honest reading of *we could not
look* is not *somebody is working*.

**A directory holding none of these files is refused rather than given a state.** `Observe` returns
a failure under `NotARunDirectory`. The predecessor caught every exception and returned one
sentinel, so a corrupt database and a directory that was never a run both reported *required run
metadata is missing* — a claim about a run that does not exist.

> This section argued the opposite until 2026-08-13 — that a running run and an interrupted one are
> indistinguishable, and that telling them apart would mean claiming to know something about a
> process that is not there to be asked. `0029` decided otherwise two days after that was written,
> and the argument was left standing in `S-16` and in `BundleLayout` for months while the code did
> the right thing.

**`RunStateObservation.RecordedUtc` is the moment the run recorded for itself**, and it is null for
a run that recorded none. A sealed run says when it completed — read by `RunCompletionReader` and
only once the seal is intact, so a bundle whose seal does not match is never asked what it says
about itself. A run that ended badly says when it stopped. A run that was interrupted, or one still
being written, never got to say anything, and null is the statement that this run did not record
when it happened rather than a missing value to be filled in with the file system's answer.

`RunStateNames.Persist` writes a state down and `RunStateNames.Read` reads it back, returning a
failure rather than a state for anything it does not recognise.

## The outcome file

`RunOutcome` has two members and no member for success. A finished run is already saying it
succeeded by having sealed evidence, and a second artefact repeating that would be a second answer
to one question. `RunOutcomeFile.Write` records an ending and `RunOutcomeFile.Read` reads one back;
those two are the whole surface. Where the file lives is `BundleLayout`'s, because a bundle's file
names have one owner. Its contents are `RunOutcomeContents.Outcome`, `RunOutcomeContents.Detail` and
`RunOutcomeContents.EndedUtc`.

> `S-18` named two members of `RunOutcomeFile` that do not exist — *PathIn* and *FileName*, written
> without backticks here so that this page's own gate does not read the correction as a claim.
> Neither ever existed in this repository. The gate that bound `S-18` checked only that every member
> of the code was named in the document, never that every member the document named was in the code
> — so two invented members sat in a bound document for a month. The gate on this page checks both
> directions, and this paragraph is what proved it.

**An outcome file that exists and cannot be read makes the run `Damaged`**, not `Interrupted`. The
run said something about how it ended and we cannot make it out, which is the same distinction the
seal draws between `Unreadable` and `Absent`.

> `S-18` recorded on 2026-08-12 that nothing writes an outcome file and that `RunOutcomeFile.Write`
> has no caller. That has not been true since `CaptureRun.End` was written: every path that ends a
> capture badly writes the file before returning, and the state a badly ended run reports is the one
> it recorded rather than `Interrupted`. Verified against the code during the pass that consumed
> `S-18`.
