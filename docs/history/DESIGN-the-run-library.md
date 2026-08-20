# Design — the run library

**Status: decided 2026-08-12.** The decision this document existed to support is recorded in
[`0025`](../decisions/0025-the-run-library-is-a-managed-root.md) — a managed root, configurable, with
no second tier and no arbitrary per-run destination — and the comparison half in
Nothing here is built yet
and no test binds it; this remains the review that informed those records, kept because the reading
behind a decision is worth more than the decision alone.

> **Corrected 2026-08-13 in `S-26`, as `F-S26-5`.** The comparison half is built. `0026`'s closed
> set of outcomes is `ComparabilityOutcome` in `SecureAD.Evidence`, the verdict is
> `RunComparability`, and `RunComparabilityDocumentationTests` binds the outcome table in both
> directions as `0026` asked for by name. The run library itself is not built - rows `F13` to `F16`
> are deferred to phase 3 - so the sentence is right about this document's own subject and wrong
> about the record it points at.

The question it was written to answer was **where a bundle lives, and whether there is a catalogue at
all.** It blocked C10 (bundle layout), the failed-run deletion the owner ruled on, and the baseline
and comparison work in
[`DESIGN-measuring-and-comparing-risk.md`](DESIGN-measuring-and-comparing-risk.md).

## The run library is not "where files go"

That is its smallest part. It does five jobs:

| Job | What it provides |
|---|---|
| **Catalogue** | List the runs that exist; turn a directory on disk into a described, listable run |
| **Naming** | Display names, notes, and a sensible default when a run was never named |
| **Comparison support** | Nominate a baseline, clear it, group runs that are comparable |
| **Lifecycle** | Promote, delete, and reclaim runs whose process died mid-capture |
| **Path safety** | Resolve and validate every caller-supplied path before acting on it |

**The consequence for the decision:** if an operator names an arbitrary destination for each run,
there is no catalogue. Nothing to list, nowhere for a baseline to live, and comparison cannot offer
"runs comparable with this one" because it does not know what exists.

## Worth adopting

- **The path handling is a real traversal defence, not a gesture.** Containment normalises both
  sides, requires a trailing separator and rejects the root itself; the identifier check rejects
  rooted paths, both separators, `.`, `..` and invalid filename characters. Every public entry point
  taking a caller-supplied path routes through resolution first.
- **Promotion inspects the database rather than trusting the metadata record** before treating a run
  as sealed. It does not take a summary's word for it — which, given what this session found about
  summaries, is the right instinct.
- **A run whose profile is unknown is grouped alone, not pooled with other unknowns.** The reason is
  recorded and is sharp: not knowing a run's profile is not evidence that it shares one with every
  other unidentified run, and pooling them would offer them to each other as acceptance sources.
- **An unreadable run reports as corrupt, not as in-progress.** A comment records the bug it fixed:
  the two used to be indistinguishable, so every picker that filtered for sealed runs silently
  dropped it and told the user nothing.
- **Two optional columns are read separately from the main metadata query**, so a bundle missing one
  does not throw away five other facts with it.
- **Staleness ignores the write-ahead log and shared-memory files**, so an abandoned `-wal` does not
  make a dead bundle look alive.
- **The connection pool is cleared before deleting a bundle.** Without it the delete fails on Windows
  every time, and the failure is swallowed — so reclamation silently does nothing.

## Must not come across

- **`manifest.json` is read in two places and written in none.** Two live behaviours depend on a file
  that never exists, and the serious one is this: a bundle with no run table but a manifest present
  is treated as **sealed** — a run declared complete on the strength of a file's existence, with no
  check of its contents. The help text also tells users the bundle contains "manifest.json — artifact
  listing with SHA-256 hashes", which it does not.
- **Two incompatible writers for one metadata file.** One writes a record with snake-case naming, the
  other builds a dictionary by hand. Marking a baseline on a run saved through the dialog either
  throws on a large object count — and the surrounding `catch { }` then discards *all* prior user
  metadata — or rewrites an array as a stringified blob.
- **Four candidate locations for the database, three of them labelled legacy.** Per
  [`0001`](../decisions/0001-no-backward-compatibility.md) three cannot occur.
- **Reclamation's correctness is a temporal precondition with nothing enforcing it.** It is safe only
  because a single application instance is enforced and it runs before any capture starts. Its own
  remarks say: *"Must be called before any capture starts, or it will delete that capture's own
  bundle."* This bears directly on the ruling that failed runs are deleted.

## The options

**A — a managed library.** The tool owns a root directory; runs are created inside it; the root is
configurable. Catalogue, baselines and comparison all work. The operator has one folder to restrict
write access to, which fits the recommendation in
[`0020`](../decisions/0020-the-seal-detects-corruption-not-tampering.md). "The operator decides" is
honoured by choosing the root rather than a path per run.

**B — no library.** A destination per run and no catalogue. Simplest to build. Comparison and
baselines become the operator's problem: they must locate both bundles themselves, and nothing can
offer a list.

**C — both.** A default managed root, plus capture to an arbitrary path, plus registering an outside
bundle into the catalogue. Most flexible, and it introduces a state the others do not have: catalogue
entries pointing at bundles that have moved or been deleted.

## What the decision also settles

- **Where a failed run's bundle is deleted from.** The owner ruled on 2026-08-12 that a failed run is
  deleted and the operator told what happened. Deleting safely requires knowing what a bundle
  directory *is* — which is this decision — and the containment guard above.
- **Whether the log tree stays separate from the bundle.** The separation is what lets a failed
  bundle be deleted without destroying the account of why it failed. The previous implementation
  pruned logs to the newest twenty-five run folders while keeping bundles until deleted, so the
  cheap explanation expired and the expensive artefact did not. With failed bundles now deleted, that
  inversion applies only to successful runs, and the fix is to copy the log into the bundle at seal
  so retention follows the artefact it describes.
- **Where a deleted run's summary tombstone lives**, per
  [`DESIGN-measuring-and-comparing-risk.md`](DESIGN-measuring-and-comparing-risk.md).

## Two identities, and only one of them carries domains

Added 2026-08-12, correcting this document. It previously said that with one forest there is one
profile, so profile grouping collapses to a single nominated reference run. That reads the
predecessor's identity model as one axis when it is two, and the distinction is the whole reason the
baseline question has an answer.

- **`ProfileId`** is a hash of the forest FQDN and nothing else. It answers **same target**, and its
  own remarks say it "deliberately says nothing about how much of that forest a given run covered".
  It is a pure function of the forest, which is why a bundle whose metadata was never written can
  still be placed in the right group.
- **`CoverageId`** is a hash of the declared domain set plus the applied OU exclusions. It answers
  **same evidence**. This is the axis that carries domains, and it hashes what the run *declared*,
  not what it achieved — so a controller dying at hour two does not strand the run on its own
  permanent comparison island. Exclusions are part of the identity because an excluded subtree drops
  objects and drops group members living under it, which is the same edge-dropping effect as an
  uncaptured domain.

So runs of one forest with different domain sets are one profile and several coverages. Two forests
are two profiles. Both cases were handled; not by the same mechanism.

## Decided

- **A — the managed library**, with the root as configuration rather than hardcoded. See
  [`0025`](../decisions/0025-the-run-library-is-a-managed-root.md).
- **The baseline survives, and belongs to a forest.** Splitting it by coverage as well was
  considered and rejected: the attestation ladder already denies baseline eligibility to every run
  that would make the second axis necessary.
- **Profile grouping survives**, at a cost of nothing, because a bundle can still be copied into the
  root by hand and the key stops it being offered as a partner for a forest it does not belong to.
