# S-16 — The bundle

**Partly consumed by the documentation rewrite.** Everything this document said about the schema —
the table list and its markers, descriptor deduplication, the three ways to produce no entries,
`ace_type` holding a number, the entry-set hash, `captured_object`'s non-catalogue columns, the
page size, the indexes, migrations, what is refused against what is recorded, and the one way in —
moved to [`what-a-bundle-holds.md`](../evidence/what-a-bundle-holds.md), corrected against the
code. `BundleDocumentationTests` and `HistoricalRecordDocumentationTests` are retargeted onto it,
and the table markers moved with them.

**Two claims did not survive the move.** This document said a bundle is four files, where
`BundleLayout` defines six — `run-outcome.json` and `preflight.json` were missing. And it said
`captured_object` carries five columns not derived from the attribute catalogue, where it carries
six; the missing one is `parent_dn`, which exists because a distinguished name looks like a
delimited list and is not one.

**What remains here are the two sections still owed a home** — what a bundle is on disk, and the
seal. Both go to `docs/evidence/the-bundle-on-disk.md`, and this file is deleted when they land.

---

What a bundle is, and what stops a half-written one being read as a whole one.

Everything this product ever says, it says from a bundle. Nothing is said from a live directory.
That is what lets a finding be reproduced a year later on a machine that has never seen the
forest — and it is why this document exists before the screens that will read it.

## What a bundle is on disk

A bundle is **one directory**, and where it lives is an argument the operator supplies. Nothing
picks a location on the operator's behalf, because a tool that decides for itself where several
gigabytes of evidence go is a tool that fills the wrong disk.

| File | What it is |
|---|---|
| `evidence.db` | The evidence. Present only on a bundle that finished |
| `evidence.db.seal` | The seal covering `evidence.db` |
| `annotations.db` | The customer's notes, acceptances and declared scope. Created empty at seal time |
| `evidence.db.partial` | A run that has not finished, or did not |

**The name is the mechanism.** A run writes `evidence.db.partial`. Renaming it to `evidence.db`
is the last act, after the write-ahead log is folded back in and after the seal is written. A
reader opens `evidence.db`, so a run that was interrupted has no file by that name to offer it.

This is the answer to *what stops a half-written bundle being opened and read as a whole one*, and
it is deliberately not a check. A check has to be remembered at every place a bundle is opened. A
name has to be remembered nowhere: the partial file is not called the thing readers ask for, and
that is true whether or not anybody thought about it.

**A crashed run and a running one are told apart, and the file system is what answers.** Both
present a `.partial` file and no `evidence.db`, so the files alone cannot say — but per
[`0029`](../decisions/0029-a-run-that-ends-badly-says-so.md) the question is whether anything still
holds the partial file open. Nothing does once the writing process ends, whatever ended it, because
the operating system releases handles when a process dies. `RunStateReader` performs that check. A
recorded heartbeat or a process identifier would need cleaning up after a crash, which is precisely
the moment nothing is running to clean it.

A run that ended badly also leaves `run-outcome.json` saying which ending it was. A missing outcome
file is not an error — it means the run stopped without being able to say why, which is reported as
*interrupted*.

> This section argued the opposite until 2026-08-13 — that the two are indistinguishable and that
> telling them apart would mean claiming to know something about a process that is not there to be
> asked. `0029` decided otherwise two days after that was written, and the argument was left
> standing here while `BundleLayout` recorded the correction.

**A failed run's `.partial` file is left where it is.** Nothing deletes it. Reclaiming disk on a
failure path destroys the only record of how far the run got, on a judgement made by the code that
has just failed, and the file has no name any reader asks for — so leaving it costs disk and never
a wrong answer.

**Why more than one file at all.** Write-ahead logging keeps recent changes in a `-wal` file
beside the database until a checkpoint folds them back
([copying a database](https://learn.microsoft.com/dotnet/maui/data-cloud/database-sqlite#advanced-configuration)),
so during a run the evidence is genuinely spread across several files. Write-ahead logging is on
because it is what the provider's guidance points to for throughput: SQLite has no asynchronous
I/O, and the async methods run synchronously
([async limitations](https://learn.microsoft.com/dotnet/standard/data/sqlite/async)). That is also
why every method on the writer is synchronous. An `async` surface here would await nothing and
mislead every caller about what it costs.

## The seal

The reasoning is `0019`. What matters at the
point of use:

**What it proves.** The bytes of `evidence.db` are the bytes that were there when the run declared
itself finished.

**What it does not prove.** It is not a signature and is deliberately not called one — there is no
key anywhere in this product, so anyone who can rewrite the evidence file can rewrite the seal
beside it. It catches corruption, truncation and casual editing, and not a determined party. It
says nothing about whether the capture was **complete**: that is a claim the bundle makes in its
own `bundle` and `partition_coverage` tables, and the seal only proves the claim has not been
edited since it was made. And it says nothing about whether the capture was correct.

**Verification has four outcomes**, and only the first opens a bundle.

| Outcome | What was observed |
|---|---|
| `Intact` | The seal is present, readable, and matches |
| `Absent` | There is no seal file. Unreachable for a bundle this product wrote, because sealing precedes the rename — so it means the directory was assembled by hand |
| `Unreadable` | A seal file exists and cannot be read. **Not** the same as `Absent`: the one thing that certainly happened is that something happened to the seal |
| `Mismatch` | The seal was read and the file does not match it |

Folding `Unreadable` into `Absent` would render a failure as a benign absence, which is the one
shape of defect an audit tool cannot have.

There is no cached verdict. Reopening a large bundle re-hashes it every time, which costs real
seconds on a bundle of some gigabytes. That cost is accepted, because a cache whose function is to
avoid performing an integrity check is a way for the check to silently never run.
