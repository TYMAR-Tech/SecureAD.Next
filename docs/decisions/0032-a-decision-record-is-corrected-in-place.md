# 0032 - A decision record is corrected in place, and git is the history

Date: 2026-08-12
Status: Accepted

Replaces the *append-only* and *supersede instead* rules in
[`docs/decisions/README.md`](README.md).

## Context

The folder rule was: never edit a record, because a record is a dated account of what was believed
at the time and rewriting one falsifies it. Reversals were recorded by writing a new record and
marking the old one superseded.

The rule was written as though the file were the only copy of its own history. **It never was.**
Every prior version of every record is recoverable from any commit, so editing a record destroys
nothing. The cost the rule was paying for does not exist.

What the rule did cost is visible in this folder today.

**A correction at the top of a file does not reach a reader who greps.** On 2026-08-12 a
cross-reading found five accepted records describing the bundle as *signed* when
[`0020`](0020-the-seal-detects-corruption-not-tampering.md) had established there is no key in this
product. The corrections were applied as notes on each record's status line. A `git grep` for
*signed* returns the offending line from the body and nothing else - no status line, no header, no
date. The correction is real and invisible in the reading mode most used.

**A whole-file supersession marker is too blunt when only part of a record changed.**
`0019` was marked superseded by `0020`, which replaced only
what the seal proves. Its partial-file rename rule - the mechanism that stops a half-written bundle
being read as a whole one - survived in code with no live record naming it, and a session that read
`0019`, saw *superseded* and moved on would have lost it.
[`0029`](0029-a-run-that-ends-badly-says-so.md) had to restate it four days later.

Both failures are the same shape: the correction and the wrong sentence are in different places, and
only one of them travels.

## Decision

**The `## Decision` section is corrected in place.** A Decision is an instruction to be executed. When
a later decision changes it, the wrong instruction is edited to the right one and deleted, not
annotated - an instruction carrying both its versions is ambiguous about which to follow.

**The `## Consequences` section is corrected in place too**, on the same grounds. A consequence is a
claim about what is true now - *"an integrity signature is only ever issued over evidence some build
already vouched for"* - and a false claim about the present misleads exactly as an instruction does.
This clause was added hours after this record was written, when applying it to `0003` found a
consequence the original wording did not cover.

**The `## Context` section is left as written, and the superseded claim is marked inline where it
sits.** Context is why we believed something, and a wrong *why* is evidence of how the error entered.
`0003`'s reasoning from an integrity signature is what makes the mistake reproducible. It must not
read as current, so the claim is marked on its own line rather than at the top of the file.

**The header states what changed and names the record that changed it**, for a reader skimming.

**Git is the archive.** No record carries a *Previously* block. A prior version is retrieved with
`git log -p` on the file.

**The test, applied line by line:** *would a grep hit on this line, with no surrounding context,
mislead someone?* If yes, the line changes. If no, it stays.

**A record is still never deleted, and its number is never reused.** Supersession remains the right
answer when a whole record goes, as `0031` did to `0007`. What changes is the treatment of a record
that is partly wrong.

**A supersession marker names where each part of the record went**, so a reader who stops at the
marker knows nothing was lost. A bare *superseded by NNNN* is a claim that everything here is dead,
and it is usually not true. `0019` is the case: marked superseded by `0020`, which replaced only the
tamper framing, while its partial-file rename rule sat behind the marker with no live record naming
it until `0029` restated it four days later - and its sentence *it is called a seal and not a
signature, because it is not one* sat there too, four days before five other records were found
still calling a bundle signed.

## Consequences

A reader arriving by grep, by a ranged read, or by opening the file gets the same answer. That is
the property being bought, and it is bought for the reader who actually consumes these records most.

**Nothing can enforce this.** No test can decide whether an edit corrected an instruction or
rewrote reasoning to look better than it was. It is a judgement call each time, on the same footing
as whether a record is any good - which has never been testable either, and is stated as a limit in
[`0011`](0011-rebuild-documentation-is-written-fresh-and-bound-by-tests.md) rather than pretended
away.

The temptation this opens is real: editing a record until it reads as though we were right all
along. The guard against it is the Context section, which is why it is exempt. A record whose
Context has been tidied has lost the only thing it was for.

Correcting a record now obliges the same sweep any decision does - every document, ledger row and
comment that repeated the wrong claim. That is not new work created by this record; it is work that
was always owed and was previously satisfied by a note nobody could see.
