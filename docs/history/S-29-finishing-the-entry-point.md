# S-29 — Finishing the entry point

> **This records session S-29 as of 2026-08-10. Nothing here states current behaviour.**  
> It is kept for the reasoning it carries, not as documentation. See [`docs/history/README.md`](README.md).

The slice document for [`S-29`](../next/sessions/S-29-finishing-the-entry-point.md). It records what
building the composition root and running it against a real forest found.

The session closed `F-S28-1` and `F-S28-2`, finished ledger rows `A7` and `A9`, and produced the
console executable. **The first real capture then found three more defects, two of them in code the
session had just written and one of them in code that had been passing tests for weeks.** That is
what the lab session was for.

## What now exists

An operator names one controller and a run library root, and gets a sealed bundle:

```
securead --library C:\SecureAD-Runs --controller addc.ad.lab [--validate]
```

Verified against a forest of one empty root domain and two children on 2026-08-10: three domains
discovered from the forest's own cross-references, four application partitions named as unread,
6,359 objects, 12,551 access control entries and 362 distinct security descriptors in five seconds,
every partition read over `SignedAndSealed`.

## The pattern this session is really about

Four of the six findings below are the same shape, and it is the shape
[`README.md`](../next/README.md) § Gates already names: **a check that cannot fail, in a world that contains
no failing case.**

- `F-S28-2` — an assertion about unread partitions, against a model publishing only partitions it
  read
- `F-S29-1` and `F-S29-2` — the whole capture path verified against attribute values in a shape no
  directory sends
- `F-S29-3` — a completeness flag that is false on every domain in every capture that will ever run

The first was found by review. **The other three were found by pointing the product at a real
directory**, and none of them could have been found any other way, because in each case the tests
and the product agreed with each other and both were wrong about the world.

## Findings

### F-S28-2 — the test that should have caught `F-S28-1` passed while measuring nothing

Carried over from [`S-28`](S-28-the-entry-point.md), where it is described in full.

- **How it was acted on:** `ControllerModel` gained a DNS application partition it publishes and a
  cross-reference answer, and the assertion was rewritten to name the partition it expects left
  unread.
- **What was learned doing it, and it is the point:** the brief's prescribed fix — give the model an
  application partition — **was not sufficient on its own**. With the partition added the assertion
  still passed, for a *new* trivial reason: the over-reading implementation planned everything
  published, so nothing was left over. Only rewriting the assertion to name the expected partition
  made the two implementations distinguishable. A session that had followed the brief and moved on
  would have left the test as vacuous as it found it.
- **Mutation directions observed:** against the unchanged implementation, both new assertions fail —
  `NotRead` is empty where the partition was expected, and the cross-reference search base is null
  because that read is never issued. Against the fixed implementation, both pass.
- **Status:** **CLOSED**.

### F-S29-1 — a controller was blamed for an attribute this product could not read

- **Severity:** correctness — the product told an operator something false about his directory
- **Confidence:** verified against a live domain controller, and mutation-tested
- **Evidence:** the first `--validate` against `addc.ad.lab` failed with *"addc.ad.lab did not state
  configurationNamingContext in its RootDSE"*. It had. Every domain controller does. A live
  directory returns attribute values as raw bytes, and the two helpers reading the RootDSE and the
  cross-references selected values with `OfType<string>()`, which discards a `byte[]` silently.
  `LdapEntryReader.AsText` — the conversion this product already owns, which accepts either shape —
  was never called.
- **What happens to a user:** an operator is told his domain controller is not one this run can plan
  against, and sent to investigate a forest that is working correctly. The message even asserts that
  a controller which does not publish the attribute is unusable, which converts a defect in this
  product into a confident claim about the customer's directory. This is precisely what
  [`0002`](../decisions/0002-absent-view-means-degraded-run.md) forbids: unavailable output is never
  phrased as a statement about the directory.
- **Why it is this way:** `LdapEntryReader.ForEntry` — the only method that builds a reader from a
  real search response — **had no test at all**. Every test used `ForValues` with ready-made .NET
  strings, a shape no controller sends. The product and its tests agreed with each other, and both
  were wrong about the wire.
- **How it was acted on:** both helpers now convert through `AsText`. A value that is present and
  cannot be read is a distinct failure with its own code, and a test asserts the words *did not
  state* cannot appear for it. `ControllerModel` now serves text as bytes **by default**, because
  the alternative is a world no controller lives in.
- **Mutation directions observed:** reinstating the filter reproduces the lab failure exactly, on
  the same attribute with the same message; removing it returns the suite to green.
- **Status:** **CLOSED**, commit `cd034e0a`.

### F-S29-2 — every text attribute in the forest was about to be stored as binary

- **Severity:** correctness — evidence would have been stored in a form nothing downstream can read
- **Confidence:** verified against a live domain controller, and mutation-tested
- **Evidence:** the first real capture died three objects in, on `cn` in the configuration partition,
  against `BundleWriter`'s own guard that storage must match what the catalogue declared.
  `BundleCaptureSink` chose between text and binary **by the runtime type of the value** — whether it
  happened to be a `string` or a `byte[]` at that moment. Since a live directory sends text as bytes,
  every text attribute in the forest took the binary branch.
- **What happens to a user:** without the writer's guard, a bundle in which every name, every
  distinguished name and every class was a blob — and every rule that reads them finds nothing,
  which renders as a forest with no findings. **The guard is the reason this was a loud crash at
  object three rather than a clean-looking bundle.** It was right and the sink was wrong.
- **Why it is this way:** the same gap as `F-S29-1`, and it survived that fix because the fix was
  incomplete. `ControllerModel` was made to serve the RootDSE and cross-references as bytes, but
  **ordinary object attributes were left as strings**, so the capture path stayed in the unrealistic
  world that caused both defects. The suite was green at 837 while the product could not write a
  single real object.
- **How it was acted on:** storage is taken from the catalogue and the value converted to match. An
  attribute absent from the catalogue was never requested, so its arrival is now reported as a fault
  in this product rather than stored by guesswork. The model now serves bytes everywhere — page
  reads and range retrievals included.
- **Mutation directions observed:** restoring the runtime-type choice reproduces the crash exactly,
  same guard and same exception, on `objectClass` instead of `cn`.
- **Status:** **CLOSED**, commit `34df4f35`.

### F-S29-3 — two coverage records in one bundle disagree about the same domain

- **Severity:** correctness — a customer asking one question of the evidence gets two answers
- **Confidence:** verified by reading the bundle produced on 2026-08-10
- **Evidence:** ask whether `ba.ad.lab` was fully read. `domain_coverage` says `Read` and
  `bundle.coverage_is_complete` is 1. `partition_coverage.is_complete` says 0, for all three domains.
  Neither row is false; they mean different things and nothing says so.
  - `PartitionCoverage.IsComplete` is defined as `!ReferralsSuppressed`. Referrals are **always**
    suppressed on a domain partition, deliberately, because that is what stops a paged search being
    ended after one page by a chased subordinate referral (`CaptureUnit`, and the Microsoft article
    it cites). So that column is 0 for every domain partition in every capture that will ever run —
    a flag that can only say one thing, which is the pattern above.
  - `RunCoverage` is built by marking every declared domain `Read`, on the reasoning that fail-fast
    means a failed unit never reaches the seal. True for hard failures, and it measures nothing about
    a degraded one.
- **What happens to a user:** a reader building a coverage summary picks a table. One choice reports
  a forest fully covered; the other reports three domains incomplete on every run ever produced. The
  honest answer — *read in full, with referrals deliberately suppressed* — is not expressible in the
  bundle at all.
- **Why it is this way:** `PartitionCoverage.IsComplete` was written when suppression was a
  connection property that might vary. It is now invariant for domain partitions and the flag was
  never revisited. The run-level record was added in this session and asserted rather than derived,
  because there was no obvious thing to derive it from — which is the same absence from the other
  side.
- **How it will be acted on:** **not fixed in this session.** It needed a decision about what a
  bundle should say, which is the owner's rather than a coding choice. Two definitions of one word
  is what gate 2 exists to prevent, so one of them stops existing.
- **Decision:** taken by the owner on 2026-08-10, in two parts.
  1. **Referral suppression is not a completeness question.** It is a deliberate setting and is
     recorded as one. Completeness means only *everything the run tried to read, it read*.
     `PartitionCoverage.IsComplete` therefore stops being defined as `!ReferralsSuppressed`, and the
     suppression itself stays on the row as the fact it is — a reader still needs it, because an
     empty continuation-reference list means *nothing lies below* only when referrals were not
     suppressed.
  2. **The run-level record is derived, never asserted.** `RunCoverage` is built from what capture
     actually recorded for each partition, not from a belief about control flow. There is then one
     source and the two records cannot disagree.
- **Why derived rather than asserted, since the assertion is true today:** because
  [`0040`](../decisions/0040-a-failed-domain-is-read-again-from-another-controller.md) and
  [`0041`](../decisions/0041-capture-reads-domains-in-parallel.md) are already decided and unbuilt,
  and each introduces exactly the case an assertion cannot survive — a domain read again from a
  second controller after a first attempt failed, and several domains in flight at once where one
  ends differently from the others. On the day either lands, an asserted *all domains read* keeps
  saying complete and nothing notices. A derived one changes by itself.
- **What was deliberately not done:** a third check refusing to seal when the derived answer
  disagrees with the plan. `RunCoverage.Of` already refuses a declared domain with no outcome, and
  `CaptureRun` already refuses a plan that does not cover the declaration. A third would be a check
  that cannot fire, which is the defect this session removed four instances of.
- **The trap the next session must not fall into, stated because it is easy to miss:**
  `PartitionCoverage` is only ever constructed when a partition was read successfully. Redefining
  its completeness as *everything it tried to read, it read* without more thought produces a flag
  that is **true in every bundle forever** — replacing a flag that is always false with one that is
  always true and calling it a fix. Whatever the new definition is, there must be a reachable state
  in which it is false, and a test that reaches it.
- **Status:** **OPEN** — decided, not built.

### F-S29-4 — range retrieval has never run, against a model or a directory

- **Severity:** unverified behaviour in the one code path that silently truncates evidence
- **Confidence:** verified — `attribute_blocks_fetched` is 0 on all five partitions of the real
  capture
- **Evidence:** the lab's largest group has eight members. `AttributeRange`, `LdapEntryReader.Continue`
  and the whole ranged-attribute path were exercised only by tests built from the documentation, and
  the real capture did not reach them either.
- **What happens to a user:** a group larger than the controller's `MaxValRange` — 1,500 by default —
  is returned truncated with a range marker. If that path is wrong, a prefix of a group's membership
  is stored as its membership. Nothing downstream can tell, and a privileged group whose dangerous
  members fall outside the first block is a finding this product would fail to report.
- **Why it is this way:** no lab forest has ever contained a group big enough. This is `F-S7-37`,
  owed against `B20`, and it remains owed.
- **How it will be acted on:** **a script is needed that creates enough accounts and a group holding
  more than 1,500 of them**, then a capture run against it, then a check that the stored membership
  matches the directory's exactly. Until that exists this path is unproven, and the two sessions that
  believed it was proven were both wrong for the reason `F-S29-1` and `F-S29-2` were.
- **Status:** **OPEN** — and it is the highest-value outstanding item, because it is the last place
  in capture where the product can be quietly wrong rather than loudly.

### F-S29-5 — an unattended run ended with an unhandled exception

- **Severity:** operability — a scheduled run produced nothing a person could act on
- **Confidence:** verified against the live run
- **Evidence:** `F-S29-2` surfaced as an unhandled `InvalidOperationException` and a stack trace on
  the console. No outcome file, no statement of what had happened, and an exit through the runtime
  rather than through the entry point.
- **What happens to a user:** a capture scheduled for 03:00 leaves a stack trace and no bundle.
  [`0039`](../decisions/0039-one-way-to-start-a-capture.md) requires a run to complete unattended and
  [`0029`](../decisions/0029-a-run-that-ends-badly-says-so.md) requires a run that ends badly to say
  so; a stack trace is neither. It also reads, to an operator, like something his directory did.
- **How it was acted on:** the entry point catches an unexpected fault, states plainly that it is a
  defect in this product rather than anything the directory did, keeps the detail so it can be
  reported, and exits non-zero.
- **Status:** **CLOSED**, commit `34df4f35`.

### F-S29-6 — one reference in the bundle names a domain the run did not capture

- **Severity:** unexplained, and recorded rather than guessed at
- **Confidence:** observed, not diagnosed
- **Evidence:** the real capture produced exactly one `unresolved_reference` with reason
  `DomainNotCaptured`, in a forest where all three declared domains were read in full.
- **Why this is written down rather than dismissed:** either something references a principal outside
  this forest — a foreign security principal or a trust, which is the ordinary explanation and would
  make the row correct — or the reason is being attributed wrongly, in which case a real gap is being
  labelled as an expected one. The two are indistinguishable without looking, and this document does
  not guess which it is.
- **Status:** **OPEN** — one query against the bundle settles it.

## What this says about the model

`ControllerModel` is described as *"modelled from the documentation"*, and its own comment says
plainly that it proves the rule and not the wire. That was honest and it was not enough. On the
single point where the documentation says nothing — **what shape a value arrives in** — the model
guessed, guessed conveniently, and every test in the tree inherited the guess.

It now serves values as a directory does. That is one correction, not a general defence: the model is
still built from articles rather than from a controller, and every remaining behaviour it asserts —
paging, bookmarks, range markers, referral suppression — is documentation until a real controller
says otherwise. `F-S29-4` is the largest of those still outstanding.
