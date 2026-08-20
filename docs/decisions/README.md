# Decisions

Short records of decisions that shape the product, kept so that "why is it this way" has an
answer that outlives the conversation it was decided in.

## What belongs here

A decision record answers **why**. It is not a bug report, a design document, or a task. If you
find yourself writing what is broken, that is a finding and belongs in `docs/review/`. If you
find yourself writing how the system behaves today, that is a description and belongs in the
reference document that owns it — `DATA-MODEL.md`, `CAPTURE-PIPELINE.md`, `ARCHITECTURE.md`.

Write one when a choice was made that a later reader could reasonably second-guess, and where
the reasoning is not visible from the code. A decision that is obvious from reading the code
does not need a record.

## Rules

- **Corrected in place, per [0032](0032-a-decision-record-is-corrected-in-place.md).** When a later
  decision changes a record, the `## Decision` and `## Consequences` sections are edited to say the
  right thing, because both are claims about what holds now. The `## Context`
  section is left as written and the superseded claim is marked inline where it sits, because a
  wrong *why* is evidence of how the error entered. The header names what changed.
  **Git is the history** — `git log -p` on the file retrieves any prior version, so editing destroys
  nothing. This replaced an append-only rule that put corrections where `git grep` could not see
  them.
- **The test is: would a grep hit on this line, with no surrounding context, mislead someone?**
  If yes, the line changes.
- **Supersede when a whole record goes.** Write a new record and set the old one's status to
  `Superseded by NNNN`. Both stay. Use this only when the record is wholly replaced — a blanket
  marker over a record that is partly right is how `0019`'s rename rule was nearly lost.
- **A supersession marker says where each part went.** A bare *superseded by NNNN* claims everything
  in the record is dead, which is usually untrue, and a reader who stops at the marker loses
  whatever still stood. See [0032](0032-a-decision-record-is-corrected-in-place.md).
- **Never delete a record, and never reuse a number.**
- **Nothing inherited is definitive**, per [0033](0033-nothing-inherited-is-definitive.md). The map,
  the old code and the old documentation are evidence to be checked, not answers to be adopted.
- **One decision per file**, named `NNNN-short-slug.md` with a four-digit sequence.
- **Keep it under about 40 lines.** A long one is usually two decisions, or a design document
  wearing a decision's clothes.
- **Do not cite finding numbers.** `F-01-x` identifiers route review sessions; they mean nothing
  to a reader who is not inside the review. State the fact, not the ticket.

## Format

```
# NNNN - Title stating the decision, not the topic

Date: YYYY-MM-DD
Status: Accepted | Superseded by NNNN

## Context
What was true that forced a choice.

## Decision
What was chosen, in the present tense.

## Consequences
What this makes cheap, what it makes expensive, and what it forbids.
```

## Index

| Record | Decision |
|---|---|
| [0001](0001-no-backward-compatibility.md) | The product has never shipped, so nothing is kept backward compatible |
| [0002](0002-absent-view-means-degraded-run.md) | Missing derived output is a fact about the capture, never about the forest |
| [0003](0003-refuse-to-reanalyse-an-incomplete-capture.md) | Re-analysis refuses any source that does not demonstrate a complete capture — its *signature* reasoning corrected by 0030 |
| [0004](0004-unknown-counts-name-the-failed-phase.md) | A count the run cannot vouch for renders as unknown, naming the phase — its *signing* reference corrected by 0030 |
| [0005](0005-withhold-at-the-widest-scope-that-shares-the-verdict.md) | A withheld count is withheld at the widest scope that shares its verdict |
| [0006](0006-tier-0-and-expected-admin-are-separate-sets.md) | Tier-0 membership and expected-admin suppression are separate sets |
| [0007](0007-the-product-surfaces-no-assessment-mode.md) | ~~The product surfaces no assessment mode, because it captures only one~~ — superseded by 0031, which carries the whole of it: there is no assessment mode, so there is nothing to hide |
| [0008](0008-live-verification-is-removed.md) | Live directory verification is removed; re-capture and compare is the only verification path |
| [0009](0009-greenfield-in-place-with-the-bundle-as-seam.md) | The rebuild happens in this repository, with the bundle as the seam — its seam clause superseded by 0013, its location by 0012, its *signed* identity sentence by 0030 |
| [0010](0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md) | The rule catalogue is data; the rule logic is code |
| [0011](0011-rebuild-documentation-is-written-fresh-and-bound-by-tests.md) | The rebuild's documentation is written fresh and bound by tests |
| [0012](0012-the-rebuild-lives-outside-src-with-its-own-solution.md) | The rebuild lives outside `src/` and builds from its own solution |
| [0013](0013-the-bundle-is-no-longer-a-two-way-contract.md) | The bundle is no longer a two-way contract |
| [0014](0014-capture-reads-the-schema-partition.md) | Capture reads the schema partition, and names come with it |
| [0015](0015-a-bundle-names-a-pattern-it-never-explains-one-away.md) | A delegation bundle names a pattern; it never explains one away — *signed bundle* reads *sealed* per 0030 |
| [0016](0016-the-filtered-set-replication-route-is-a-product-judgement.md) | The filtered-set replication route is a product judgement, not a documented fact |
| [0017](0017-capture-reads-the-whole-forest.md) | Capture reads the whole forest; scope is applied to reading, never to evidence — *signed bundle* reads *sealed* per 0030, and its breadth and unmeasured-cost claim corrected by 0034 |
| [0018](0018-connection-security-is-an-ordered-ladder.md) | Connection security is an ordered ladder walked from the top |
| [0019](0019-the-bundle-carries-a-seal.md) | ~~The bundle carries a seal, and only a bundle whose seal is intact is opened~~ — superseded, and nothing lost: what the seal proves and the four verification outcomes are 0020, the partial-file rename is 0029, *seal not signature* is 0030 |
| [0020](0020-the-seal-detects-corruption-not-tampering.md) | The seal detects corruption, not tampering, and only an intact bundle opens |
| [0021](0021-re-analysis-produces-a-new-bundle.md) | Re-analysis produces a new bundle and never alters the one it read |
| [0022](0022-objects-are-stored-as-typed-columns.md) | An object is stored as typed columns, and what was never captured is recorded by reference |
| [0023](0023-a-finding-has-a-stable-identity.md) | A finding has a stable identity, and an unmatched acceptance is reported rather than dropped |
| [0024](0024-a-rule-identifier-is-permanent.md) | A rule identifier is permanent and is never reused |
| [0025](0025-the-run-library-is-a-managed-root.md) | The run library is a managed root, and a baseline belongs to a forest — its exclusion reasoning replaced by 0027 |
| [0026](0026-one-answer-to-whether-runs-may-be-compared.md) | One answer to "may these runs be compared", and a card that reports it — its state table replaced by 0027 |
| [0027](0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) | Coverage varies only by failure or by the forest changing, and a failed run is refused |
| [0028](0028-one-run-state-vocabulary.md) | One run state vocabulary, and every state is observed rather than assumed |
| [0029](0029-a-run-that-ends-badly-says-so.md) | A run that ends badly says so, and whether a run is alive is asked of the file system |
| [0030](0030-the-product-produces-sealed-evidence-never-signed.md) | The product produces sealed evidence, never signed |
| [0031](0031-there-is-no-assessment-mode.md) | There is no assessment mode |
| [0032](0032-a-decision-record-is-corrected-in-place.md) | A decision record is corrected in place, and git is the history |
| [0033](0033-nothing-inherited-is-definitive.md) | Nothing inherited is definitive: the map, the old code and the old documentation are evidence, not answers |
| [0034](0034-capture-excludes-a-shipped-noise-list.md) | Capture reads every object class except a shipped list of noise; the operator switch only ever widens it |
| [0035](0035-coverage-is-recorded-once-per-capture-unit.md) | Coverage is recorded once per capture unit; domain and run coverage are derived from those rows, never asserted beside them |
| [0043](0043-a-gpos-file-permissions-are-read-below-the-root-folder.md) | A GPO's SYSVOL permissions are read for the root folder, every directory beneath it, and every file the product opens; scripts are in scope |
| [0044](0044-sysvol-coverage-is-recorded-beside-the-capture-units.md) | SYSVOL coverage is recorded beside the capture units, on the condition that its incompleteness has knowable edges; a SYSVOL failure does not fail the run |

## Finding a decision by subject

Titles state decisions, not topics, so the record you want is often not the one whose name you
would search for. This maps the questions that have been asked more than once.

| If you are asking about | Read |
|---|---|
| Which object classes capture reads; excluding noise; vendor objects | [0034](0034-capture-excludes-a-shipped-noise-list.md), then [0017](0017-capture-reads-the-whole-forest.md) |
| Whether a customer may narrow a run; scoping a report | [0017](0017-capture-reads-the-whole-forest.md) |
| Which attributes capture asks for, and of which objects | [0034](0034-capture-excludes-a-shipped-noise-list.md) and [0014](0014-capture-reads-the-schema-partition.md) |
| Why a permission GUID can be resolved at all | [0014](0014-capture-reads-the-schema-partition.md) |
| How an object's attributes are stored | [0022](0022-objects-are-stored-as-typed-columns.md) |
| What an empty grid or a missing view means | [0002](0002-absent-view-means-degraded-run.md), [0004](0004-unknown-counts-name-the-failed-phase.md) |
| Whether two runs may be compared | [0026](0026-one-answer-to-whether-runs-may-be-compared.md), [0027](0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) |
| What "coverage" means, and which grain owns it | [0035](0035-coverage-is-recorded-once-per-capture-unit.md) |
| What happens when a domain, or the schema partition, cannot be read | [0035](0035-coverage-is-recorded-once-per-capture-unit.md), [0027](0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) |
| What the seal proves | [0019](0019-the-bundle-carries-a-seal.md), [0020](0020-the-seal-detects-corruption-not-tampering.md), [0030](0030-the-product-produces-sealed-evidence-never-signed.md) |
| Connection security and what a weak connection costs | [0018](0018-connection-security-is-an-ordered-ladder.md) |
| Whether the old app settles anything | [0033](0033-nothing-inherited-is-definitive.md) |
