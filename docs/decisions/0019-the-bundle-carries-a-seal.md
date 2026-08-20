# 0019 - The bundle carries a seal, and only a bundle whose seal is intact is opened

Date: 2026-08-12
Status: Superseded, and **nothing it decided was lost** - every part is live somewhere else.
What the seal proves is [0020](0020-the-seal-detects-corruption-not-tampering.md), which also
carries the four verification outcomes, the *only Intact is opened* rule, the *Unreadable is not
Absent* rule and the refusal of a cache. The partial-file rename mechanism and the rule that a
failed run keeps its `.partial` are [0029](0029-a-run-that-ends-badly-says-so.md). That it is a
seal and not a signature is [0030](0030-the-product-produces-sealed-evidence-never-signed.md).

This record is why a supersession marker now has to say where each part went: it was marked
*superseded by 0020* when `0020` replaced only the tamper framing, and the rename rule sat behind
that marker with no live record naming it until `0029` restated it four days later. The sentence
*it is called a seal and not a signature, because it is not one* sat behind it too, and would have
caught the `signed` claim in five other records had anyone read past the marker.

## Context

[`0003`](0003-refuse-to-reanalyse-an-incomplete-capture.md) refuses to analyse a capture that
cannot demonstrate it finished, and rests that refusal on the integrity signature the run ends
with. **— There is no signature; `0020` and `0030` settled that, and `0003` is corrected.** Until
now nothing in the rebuild issued one, so the strongest claim the product makes
rested on nothing.

Two facts force the shape. Write-ahead logging keeps recent changes in a `-wal` file beside the
database until a *checkpoint* merges them back
([write-ahead logging](https://learn.microsoft.com/dotnet/standard/data/sqlite/async),
[copying a database](https://learn.microsoft.com/dotnet/maui/data-cloud/database-sqlite#advanced-configuration)),
so a hash taken over the database file mid-run covers a database that is not all there. And
there is no key anywhere in this product, so whatever is computed proves the bytes have not
changed - not who produced them.

## Decision

A run writes to `evidence.db.partial`. When capture finishes it checkpoints, closes, hashes the
file with SHA-256, writes `evidence.db.seal` beside it, and only then renames the file to
`evidence.db`. **The name is the mechanism**: a reader opens `evidence.db`, and a run that was
interrupted has no file by that name for a reader to open.

Verification has four outcomes and every one of them is named. `Intact`; `Absent`, meaning no
seal file; `Unreadable`, meaning a seal file that cannot be parsed; and `Mismatch`. **Only
`Intact` is opened.** The other three are refused, naming which one it was.

It is called a seal and not a signature, because it is not one.

## Consequences

`0003`'s gate stops being a rule about re-analysis and becomes a rule about every open. This record
read that as licence to remove re-analysis; [`0021`](0021-re-analysis-produces-a-new-bundle.md)
restored it the following day, having found that the removal rested on a summary the implementation
contradicts. The gate applying to every open is the part that survives.

The seal proves one thing: these bytes are the bytes present when the run declared itself
finished. It does not prove the forest said this, that the capture was complete, or that it was
correct - anyone who can write the file can write the seal beside it. Completeness is a claim
the bundle makes in its own tables; the seal only proves that claim has not been edited since.

A malformed seal is `Unreadable` and not `Absent`. Degrading it to `Absent` would render "the
seal is corrupt" as "nobody sealed this", and a failure rendered as a benign absence is the one
defect this product cannot have.

There is no cache that lets verification be skipped. Reopening a large bundle re-hashes it, and
that cost is accepted: a cache whose purpose is to avoid performing the check is a way for the
check to silently never run.

A run that fails leaves its `.partial` file exactly where it is. Nothing deletes it, because a
product that reclaims disk on a failure path destroys the evidence of how far it got.
