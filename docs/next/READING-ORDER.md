# Reading the rebuild — the path one object takes

This is a **reading order**, not a summary. It names the files in the order a single object travels
through them, and says what question each one answers. It exists because the code is organised by
component and the logic runs across components, so reading alphabetically teaches nothing.

Read the doc comments first in each file. They explain *why*, and they are the best writing in this
repository. Skip method bodies unless something does not add up.

**Apply the repository's own rule while reading.** Per `docs/next/README.md`, nothing outside
`docs/decisions/` is settled, and that includes every comment here. Where a comment and the code
disagree, that is a finding. This document was written after reading the files it names, and the
reading turned up one such contradiction — see step 8.

---

## 1. How it connects, and what it refuses

`SecureAD.Audit/Connect/ConnectionSecurityLadder.cs` — four rungs, most protected first: LDAPS,
signed-and-sealed, signed, unprotected. Written as **data rather than branching**, because the set of
acceptable transports is decided by other people and changes.

*The question it answers:* what is this product willing to talk over?

`ConnectionLadderWalk.cs` — tries each permitted rung in order, stops at the first that answers.
Note the two different refusals at the bottom: a controller that accepted nothing at all, versus one
that accepted nothing *protected* — the second is *"a finding about the forest as much as about this
run."*

`LdapDirectoryChannel.cs` — the real socket. Note that it **interprets nothing**: a bad result code
is raised as-is, because deciding what it means belongs to `RetryPolicy` and a channel that quietly
retried would be a second failure policy.

---

## 2. Which partitions get read

`SecureAD.Audit/Capture/CapturePlan.cs` — configuration and schema partitions first, then domains.
The ordering is a decision: they are a few thousand objects, everything else is interpreted against
them, and a run that will fail on them should fail in its first minute rather than after three hours
of a customer's domain.

Also note `NotRead` — partitions the controller publishes that this run will not read. Recorded
rather than ignored.

---

## 3. The query actually sent

`CaptureSearchRequestFactory.cs` — the filter, the attribute list, the controls.

**This is the file that settles what capture asks for.** Every object is asked for the whole
catalogue whatever its class, because a search names its attributes before the object's class is
known. If you read one file in this repository, read this one: several sessions have reasoned about
capture from the catalogue's shape instead, and been wrong.

---

## 4. The page loop

`PartitionCapture.cs` — the heart of it, and mostly a list of things it **refuses** rather than
guesses:

- referral chasing must already be off, checked *before the first request*
- a page arriving without the paging control is refused
- a repeated bookmark is refused
- an empty page is accepted, because a controller may legitimately send one

The opening comment explains the failure this exists to prevent: a chased referral destroys the
paging bookmark inside the LDAP runtime, so the client reads an empty one and stops — a thousand
objects out of nine million, reported as success.

---

## 5. Turning a response into an object

`LdapEntryReader.cs` — three outcomes per attribute: complete, more to fetch, or did not come back.

`AttributeRange.cs` — why a big group arrives in blocks, and how a block says it was the last one.
The whole file is worth reading: a controller will not send more than 1,500 values by default and a
hard ceiling of 5,000 overrides any policy set higher.

`CapturedObject.cs` — the last gate. Throws if any attribute is still part-way through a range
retrieval, because *"a prefix of a group's members presented as its members"* is the defect the
range rule exists to remove.

---

## 6. The gap

**Nothing here.** `PartitionCapture` hands finished objects to `ICapturedObjectSink`, and the only
implementation in the tree is a test double. Nothing converts a `CapturedObject` into an
`EvidenceObject`.

This is the seam. Reading up to it and finding nothing is the point of this walkthrough.

---

## 7. What gets written

`SecureAD.Evidence/EvidenceObject.cs` — the bundle's own vocabulary. Note that
`StoredAttributeCompleteness` has two members where capture's has three: a half-fetched attribute has
no spelling here at all, so it cannot be written.

`BundleSchema.cs` — every table. Columns are derived from the attribute catalogue, so the schema
cannot describe a different set of attributes from the one capture asks for.

**Half of this file is current and half is awaiting rebuild.** The object storage was rebuilt; the
security-descriptor storage is pre-review and does not deduplicate descriptors as inventory row `C1`
requires.

`BundleWriter.cs` — the four refusals on the write path, and why the storage-kind check must exist:
SQLite column types are affinities rather than constraints, so text bound to a `BLOB` column is
stored silently.

---

## 8. Sealing and finishing

`BundleLayout.cs` — **the name is the mechanism.** A run writes `evidence.db.partial`; renaming it to
`evidence.db` is the last act, after the checkpoint and after the seal. A reader opens `evidence.db`,
so an interrupted run has no file by that name to offer.

`BundleSealing.cs` — four verdicts, and the fourth is a correction: folding an unreadable seal into
"absent" renders *something happened to the seal* as *nobody ever sealed this*.

> **The contradiction this walkthrough found.** `BundleLayout` records that a running run and a
> crashed one *can* be told apart — `0029` decided the question is asked of the file system, not of a
> record, by testing whether anything still holds the partial file open. `S-16` carried the opposite
> claim for five days; it has been corrected and the section now lives in
> [`the-bundle-on-disk.md`](../layers/evidence/the-bundle-on-disk.md). The code was right and the document
> was stale, which is
> the direction this repository says to expect.

---

## What to look for while reading

- **A comment that contradicts the code.** That is a finding, and the code wins.
- **A state nothing can produce.** Two have already been found this way — an object completeness that
  is the same value for every object ever captured, and a deleted-object filter for objects the
  search can never return.
- **A second name for one thing.** `CONCEPT-REGISTRY.md` exists to prevent it; *coverage* got away
  with six meanings before anyone noticed.
