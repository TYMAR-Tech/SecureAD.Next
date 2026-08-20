# 0029 - A run that ends badly says so, and whether a run is alive is asked of the file system

Date: 2026-08-12
Status: Accepted. Amended 2026-08-16 by
[`0058`](0058-a-run-may-be-stopped-and-stopping-it-keeps-nothing.md): **cancellation is no longer
one of the endings that writes into the bundle directory.** A run the operator stops keeps nothing
and must not appear in the run library, so its marker is written where the library does not read.
This record now governs failure only.

Restates the partial-file mechanism decided in [`0019`](0019-the-bundle-carries-a-seal.md), which
is marked superseded by [`0020`](0020-the-seal-detects-corruption-not-tampering.md) even though
`0020` replaced only what the seal proves. The rename rule survived in code and tests with no live
record naming it, so a session reading `0019`, seeing *superseded* and moving on would have lost it.

## Context

A bundle is one directory holding four files. A run writes `evidence.db.partial`; when it finishes
it checkpoints, closes, hashes the file, writes `evidence.db.seal` beside it, and only then renames
the file to `evidence.db`. **The name is the mechanism**: a reader opens `evidence.db`, so a run
that did not finish has no file by that name to offer one. A run that fails leaves its `.partial`
exactly where it is, because a product that reclaims disk on a failure path destroys the evidence
of how far it got.

That is a good mechanism and it is kept. Its consequence is that **every bad ending looks the
same.** A failure, a cancellation, a reboot and a capture that is running at this moment all
present one `.partial` and no `evidence.db`. The run library, which [`0025`](0025-the-run-library-is-a-managed-root.md)
makes responsible for listing runs and deleting the ones that failed, therefore cannot say why a
run did not finish, and cannot tell a dead run from a live one - so it would offer a delete button
beside a capture still in progress.

## Decision

**A run that fails writes a run-outcome file into its bundle directory**, recording when it ended
and the reason in the words the operator should see. A failed run appears in the run library, so the
operator can see that it happened and why.

**A run the operator cancelled is not covered by this.** Its marker is written outside the bundle
directory, because the library enumerates those directories and a cancelled run must not become a
row in it. See [`0058`](0058-a-run-may-be-stopped-and-stopping-it-keeps-nothing.md). *This record
originally wrote one file for both endings; the wording is corrected here because a grep hit on the
old sentence would state the wrong rule.*

**Only a bad ending writes one.** A successful run does not, because `evidence.db` and an intact
seal already say it succeeded, and a second artefact saying the same thing is a second answer to
one question - the defect the concept registry exists to prevent.

**Whether a run is alive is asked of the file system, not of a record.** The test is whether
anything still holds the partial file open. Nothing does after the writing process ends, whatever
ended it, because the operating system releases handles when a process dies. A recorded heartbeat
or a process identifier would need cleaning up after a crash, which is exactly the moment nothing
is running to clean it.

**The outcome file is outside the seal, and is not evidence.** It has to be outside: a failed run
has no `evidence.db` for a seal to cover. It is therefore not tamper-evident, and nothing that
reads it may present it as proof of anything. It describes a run that produced no evidence, and no
security conclusion rests on it.

**A missing outcome file is not an error.** It means the run stopped without being able to say why,
which is reported as interrupted per [`0028`](0028-one-run-state-vocabulary.md).

## Consequences

The six run states in `0028` each become reachable from something observed. Without this record
four of them would be indistinguishable, and a vocabulary whose words cannot be arrived at is the
dead-member failure `docs/next/README.md` names first.

**Capture acquires an obligation on its failure paths**, which is where code is least exercised.
The risk is accepted for a specific reason: if the write fails, the state degrades to *interrupted*,
which is a true statement about what is known rather than a false one. There is no reading of this
mechanism that produces a wrong claim to a customer.

A run killed outright, or a machine losing power, writes nothing and reports as interrupted even if
a cancellation had just been requested. That is the limit of what the evidence supports and it is
reported as such rather than guessed at.

The liveness test is a check and not a write, so it never modifies a bundle it is only listing -
which matters because [`0020`](0020-the-seal-detects-corruption-not-tampering.md) requires that
opening a bundle never alters it.

This changes nothing about comparison. All four not-completed states refuse a comparison
identically under [`0027`](0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md). What
is bought is entirely what the library can tell an operator who is deciding what to delete and what
to run again.
