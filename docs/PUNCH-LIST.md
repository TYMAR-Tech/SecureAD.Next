# Punch list

Work the documentation identified that the code has not done.

**One line per item.** Reasoning that explains *how the product works* belongs in the layer docs, not
here. This file exists to be read in one sitting — if it stops being readable in one sitting it has
stopped working.

**Nothing here is scheduled.** Items are recorded so they are not lost between sessions, and are
deliberately not fixed during a documentation pass.

Status: `open` · `blocked` (a named input is missing) · `decision` (needs an owner ruling) ·
`conflict` (sources disagree)

---

## Kernel / Security

| ID | Item | Status | Blocked on |
|---|---|---|---|
| P-14 | A confidential-attribute read is reported as a takeover on `READ_PROPERTY` alone, without consulting `CONTROL_ACCESS` | decision | soften the sentence now, or wait for layer 3 |
| P-15 | Class schema is not captured, so *attributes applicable to this object* cannot be answered | blocked | capture change |
| P-13 | `DaclWasCanonical` is a `bool` where the evidence supports four states | blocked | capture of forest functional level and `fDontStandardizeSDs` |
| P-7 | The DACL walk is bounded by `AceCount` alone; `AclSize` and `AclRevision` are never read | open | — *(the lab disagreement once cited as corroboration is explained by deduplication; see below)* |
| P-16 | `PASSWD_CANT_CHANGE` is stated as current state; it is enforced by permissions, not by the bit | open | — |
| P-12 | `DaclState` has four of the six states the review recommended — `Absent` is folded into `Null`, `NotRetrieved` has no equivalent | open | — |
| P-10 | The classifier mixes ACE semantics, capability and risk, and reads raw evidence directly | open | layer 3 first |
| P-11 | Risk vocabulary may have leaked into the parsing and wording layers | open | — |
| P-1 | The early-stop correction may itself over-generalise, and the sweep that found it was never completed | decision | owner ruling |

### Detail, where one line is not enough

**P-14.** Microsoft requires `READ_PROPERTY` **and** `CONTROL_ACCESS` to reach a confidential
attribute, possibly from different entries. `ClassifyAttributeRead` tests only the attribute name and
says *"reading it is the whole attack"*. It over-reports, which is the safe direction, but it is the
entry-level-as-principal-level claim that R19 forbids — the same fault already corrected for
`WRITE_OWNER`. Either soften the sentence to say this entry supplies one half, or answer it properly
in [planned effective access](planned/effective-access.md).

**P-15.** Needs class attribute definitions, superclass inheritance, and applicable auxiliary and
dynamic auxiliary classes. MS-ADTS inheritance uses the **most-specific structural class plus
applicable dynamic auxiliary classes**, not every class in the `objectClass` chain, so unioning
`objectClass` yields a larger set than AD applies. Unblocks four recorded items at once and cannot be
worked around later — a bundle captured without it can never answer these questions.

**P-1.** `AceCanonicalization` states flatly that AD examines every entry to the end of the DACL.
That is correct for simple access, but control access rights and validated writes **do** terminate at
the first applicable entry, and the specification warns against applying the general early-stop
algorithm to all AD rights. The original claim was reported corrected in six places, then three more
were found incidentally; no systematic sweep was ever done.

**P-7, and the open finding it may explain.** `docs/areas/what-a-permission-means.md` carried an
open finding, `F-4`, with real lab evidence:

> The `ace` table and the re-parse of the same descriptor disagree by one entry on `OU=test01` in
> `ad.lab-20260821-014720` — 57 against 56 — while the descriptor reports
> `dacl_completeness=Complete`.

**These were recorded as very likely the same defect. That link does not hold** — see the
adjudication below. The walk is bounded by the declared entry count and the descriptor's end rather
than by the ACL's own `AclSize`, and completeness is asserted when the parsed count equals the
declared count. That much is true of P-7. `F-4` is a different question and probably not a defect.

Consequence stated in the finding itself: *"An entry count an operator reads may be short, and a
permission may not be listed."* **Neither half of that is true today, and both were checked.**

- *A permission may not be listed.* The entry list an operator sees is `ObjectPermissions.Entries`,
  which is a fresh parse of `raw_bytes` with nothing deduplicated and nothing reordered. No
  permission is withheld from a screen by any of this.
- *An entry count an operator reads may be short.* `captured_object.ace_count` is written by
  `BundleWriter.CountEntriesPerObject` and **read by no production code in the repository** — the
  only other occurrences of the name are the two writing sites and two comments. There is no reader
  for a short count to mislead.

So this is ordinary backlog. It is still worth fixing, because a walk that trusts a declared count
over the structure's own length is wrong in a way that will matter as soon as something reads that
column, and because `AclRevision` is never checked at all. But it is not the category that is never
deferred, and the sentence that placed it there was describing a reader that does not exist.

Not yet established which of the two readings is correct.

**The two readings are now named, which they were not when this was recorded.** They are not two
runs of one routine; they are two paths the product takes deliberately.

- **Capture time.** `SecurityDescriptorParser.Parse` → `AceNormalizer.Normalize` → rows in `ace` →
  `BundleWriter.CountEntriesPerObject` → `captured_object.ace_count`.
- **Read time.** `ObjectPermissionsReader.Read` parses `security_descriptor.raw_bytes` afresh and
  builds `ObjectPermissions.Entries` from that, **deliberately not from the `ace` table** — its own
  remarks say the `ace` table is the canonical projection and that `S-57` upheld that a projection
  cannot stand in for the stored DACL.

So `ace_count` and the entry list an operator sees come from different code, and the 57-against-56
is a disagreement between exactly those two. That is worth knowing before the fix pass starts,
because it rules out the obvious first guess: this is not one walk read twice, and a repair to the
walk changes one side only. The divergence is by design; the disagreement is not.

Which side is right is still open, and nothing here settles it.

**But the link between P-7 and F-4 does not survive contact with the code, and should not be
carried forward unexamined.** The `ace` table is not a second walk of the same DACL. It is the
canonical projection, and `AceNormalizer.Normalize` **deduplicates it** — `Deduplicate(canonicalAces)`
after the sort — so a descriptor carrying the same entry twice yields one row. The read side does
not deduplicate, deliberately: *"a DACL carrying the same grant twice is what the directory holds
and a reader deciding it meant once is editing evidence."* `ObjectPermissions`'s own remarks record
the measurement — lab bundle `ad.lab-20260819-232425`, **12,603 stored against 12,600 projected**,
three entries on three objects.

**So a one-entry disagreement on one organisational unit is the ordinary, designed, documented
behaviour of a descriptor with one duplicated entry, and `dacl_completeness = Complete` is correct
beside it** — nothing was lost in parsing; the projection collapsed a duplicate on purpose. That
explains F-4 completely without invoking `AclSize` at all.

**The direction of the numbers decides it, and the punch list does not record which way round they
were.** Deduplication guarantees `ace` ≤ re-parse, always. So:

- If the re-parse saw 57 and the `ace` table 56, F-4 is deduplication working as designed, is not a
  defect, and is not evidence for P-7. It should be closed and P-7 judged on its own merits.
- If the `ace` table really saw 57 and the re-parse 56, that is a **projection larger than the bytes
  it was derived from**, which deduplication cannot cause and which the `AclSize` mechanism cannot
  cause either. That would be worse than what was recorded, and would need its own explanation.

Either way the recorded adjudication — *"these are very likely the same defect"* — is unsupported.
It was written before anything read the descriptor half of the schema back out of a bundle. Settle
the direction against `ad.lab-20260821-014720` first; it is one query, and it decides whether there
is a defect here at all.

**P-7 itself is untouched by this.** That the DACL walk reads `AceCount` and never `AclSize` or
`AclRevision` is true, and is worth fixing on its own terms. What it has lost is its corroborating
evidence.

---

## Audit / Capture

| ID | Item | Status | Blocked on |
|---|---|---|---|
| P-19 | `EveryPublicTypeInTheCaptureProjectIsNamedByACaptureSliceDocument` scanned four types while claiming nineteen — green for months | open | — *(gate widened during the rewrite; the finding is kept because the shape recurs)* |
| P-20 | `F-S44-2` — the catalogue's three test suites are a closed loop anchored to the rules already written, and it has no external anchor | open | a reconciliation fixture naming every predecessor attribute or a written omission |
| P-21 | `0065` is decided and unimplemented; every run taken before it lands is permanently silent on the trust attributes | open | — |
| P-22 | `F-S40-1` — `0040` decided a failed domain is read again from another controller, and nothing walks that path | open | — |
| P-23 | Gate 5b is recorded as blocked on an entry point that now exists (`CaptureRun`) | decision | whether to turn it on |
| P-24 | `F-S23-4` — six captured attributes have no consumer among the sixty-two rules; three are named attack surfaces the product holds data for and says nothing about | open | rules at branch E |
| P-25 | `F-S23-5` — six rules need SYSVOL and nothing in the directory answers them; ten per cent of the catalogue is inert and nothing says so | open | B14/B15 |
| P-26 | `F-S7-37`, `F-S7-39`, `F-S7-40` — three claims about how a real controller behaves that no test in this repository can settle | blocked | lab session |

**P-19 detail.** The check read `typeof(CapturedAttributeCatalog).Assembly` filtered to
`SecureAD.Kernel.Capture`, which is four types. Its name and its failure message both said *the
capture project*. The fifteen public types in `SecureAD.Audit.Capture` were never scanned.

The fault arrived **by repair**: S-24 moved the catalogue into the kernel, this check failed loudly,
and the fix pointed the scan at the catalogue's new neighbours rather than at the component the test
is named for — a different set, checked against the same document, passing. Widened during this
pass, and it immediately named twelve types no document mentioned. Recorded rather than closed
because this is the third time a check in this repository has passed while measuring nothing, and
the second time the cause was a repair that preserved the assertion and moved the subject.

---

Recorded so they are not lost. Each belongs to its own pass.

| ID | Item | Subsystem | Status |
|---|---|---|---|
| `#20` | GPO link precedence — the deep review and S-58 flatly contradict each other | group policy | **conflict** |
| `#17` | `ProvesTheControllerAnswered` counts LDAP 91 as an answer, so a certificate fault can produce a forest finding | audit/connect | open |
| `F-S40-1` | `0040`'s retry from another controller is decided, and nothing walks it | audit/connect | open |
| `#19` | `gPLink` option bits are documented in the archive but never verified first-party | group policy | blocked |
| `#22` | `SecurityTemplateParser` accepts nonconformant encodings without labelling them | group policy | open |
| `#21` | `DnHelper` decides escaping from the preceding character rather than from the escape sequence | kernel/naming | open |
| P-2 | `SchemaVersionUnsupported` has no test — zero references in the test project, while its sibling refusal has one | evidence/bundle | open |
| P-3 | `security_descriptor.canonicalization_version` is sourced from the build rather than from the entries it describes, so the reader's only defence against unreproducible hashes is a restatement of its own constant | evidence/bundle | open |
| F-0079-6 | A change to `CoverageId`'s hash format silently splits every existing group, and nothing records which format produced a value | evidence/run library | open |
| F-0056-1 | No pre-capture total of unestablished facts exists | evidence/coverage | open |
| P-17 | Eleven tracked files are zero bytes, including three `.cs` files and a `.csproj` | repository | open |
| P-18 | `CaptureRunEndToEndTests` fails intermittently on a disposed SQLite handle | tests | open |

**P-17 detail.** A predecessor finding cleared the *untracked* empty files and left the tracked ones,
on the grounds that deleting tracked files is a repository change rather than a tidy-up. Those
specific files are now gone, but eleven remain:

```
next/src/SecureAD.Shell/Services/BundleTreeSource.cs
next/src/SecureAD.Shell/Services/ITreeSource.cs
next/src/SecureAD.Shell/ViewModels/SectionView.cs
next/tools/SchemaProbe/SchemaProbe.csproj
next/tools/_repoint-repository-root.ps1
next/tools/_run-inbound-next.ps1
next/tools/check-instruction-claims.ps1
next/tools/delink-archived-documents.ps1
next/tools/restore-documents-to-baseline.ps1
next/tools/tmp-probe.ps1
next/tests/.c8-row.tmp
```

`SchemaProbe.csproj` being empty means that tool cannot build, which is consistent with it not
appearing in the solution. The reasoning from the original finding still applies: **a name that
claims a task and a file that does nothing is worse than no file, because a later reader assumes it
works** — and `check-instruction-claims.ps1` and `delink-archived-documents.ps1` name tasks directly
relevant to this rewrite.

**P-18 detail.** `EveryObjectTheControllerServedIsStored` failed once with
`System.ObjectDisposedException: SQLitePCL.sqlite3`, then passed in isolation and on two subsequent
runs. Low severity but it corrodes the oracle: *"A test that fails at random trains a reader to
re-run rather than to look, and the day it fails for a real reason it will be re-run too."*

**P-2 detail — verified against the code 2026-09, and the line was right about its own subject.**
`SchemaVersionUnsupported` appears exactly twice in the repository, both in `BundleReader.cs`: the
remarks at line 66 and the failure code at line 162. Zero occurrences under `next/tests`. Checked
because the previous pass found `#17` wrong about what it named, and this one is not.

**What the check sharpens rather than changes.** The two version refusals are written as a pair in
one paragraph of the same remarks block, and only one of them was tested.
`BundleReaderTests.ABundleCanonicalisedByAnEarlierVersionIsRefusedUnderItsOwnCode` writes a bundle,
rewrites `canonicalization_version` and re-seals — so the seam for testing a version refusal exists,
is already built, and works. `UPDATE bundle SET schema_version` through the same seam is the missing
test. So this is not a refusal that is hard to reach; it is the `P-19` shape a third time — a rule
applied to a list of two, and the second entry never re-asked. The area file understates it further:
`how-a-run-is-stored.md` has a capability row for neither refusal, including the one that is tested.

**P-3 detail — adjudicated 2026-09. The mechanism is real, no bundle today carries a wrong value,
and what it costs is not the number.**

`BundleWriter.WriteDistinctDescriptor` binds `canonicalization_version` to the static
`AceCanonicalization.Version` while `normalization.Aces[n].CanonicalizationVersion` sits unread in
the same method. The two cannot disagree today: `AceNormalizer.Normalize` is the only producer of an
`AceNormalizationResult`, it stamps every entry with that same static, and its only two callers —
`BundleCaptureSink` and `SysvolCapture` — call it in process. The `ace` table has no version column
at all, so the per-entry value is dropped on the way in.

**The writer's own remarks already state the rule the insert does not follow.**
`WriteSecurityDescriptor` says the entries *"arrive already canonicalised, each carrying its own
hash and the version of the pipeline that produced it"* — and the insert twelve lines below reads
the static instead. So this is not a coupling nobody thought about; it is a stated intent and an
implementation that diverged from it, in one method, which is why it reads correct to anyone
checking the comment rather than the parameter list.

**What it breaks is the column's independence, and that is a comparability claim.** The column
exists so a later build can refuse hashes it cannot reproduce, and `BundleReader.Open` reads that
column and nothing else to decide. Sourcing it from the build makes it a restatement of the reader's
own constant rather than a fact about the stored bytes — a self-certifying loop of the shape
`F-S44-2` names, closed today only by there being one producer, which is a property of the current
call graph and not something the writer asserts. The failure it cannot catch is precise: a bundle
whose entries are version 2 and whose column says 3 passes the refusal, then compares equal to
nothing and unequal to everything, silently. `BundleSchema.cs` records that this exact thing already
happened once — the column *"was written here from the start and read by nothing until 2026-08-19,
which is how a version 2 bundle could open silently under a version 3 build."*

**The remedy, so a fix pass need not re-derive it.** Take the version from the entries, and refuse a
set carrying more than one — a descriptor whose entries were canonicalised by two recipes is not a
descriptor this product can hash, and that is a refusal rather than a warning for the same reason
the reader's is. The empty entry set keeps the build's constant and that is correct: there is no
entry to ask, and the set hash was produced by this build. One line in the writer, one guard, one
test.

**Recorded rather than fixed, and the branch stays documentation-only.** It is not urgent by the
owner's own test — no operator reads a wrong number today, because no such bundle can exist. It is
recorded at all because the thing standing between the claim and the defect is the call graph
happening to have one producer in it, and `0021` puts a second one on the roadmap: re-analysis
derives a new bundle from a sealed one, and that is exactly the path that would hand the writer
entries it did not normalise.

**F-0079-6 is the same shape, and it has already cost something.** Carried from
`the-run-library.md`. `CoverageId` is a hash over a formatted string with no format version recorded
beside it, so changing what goes into the string obsoletes every existing value while looking
identical on screen — and on 2026-08-21 it did, showing the owner two groups under one heading.
Deliberately not repaired by grouping on the domain rows instead: the fingerprint also decides
comparability, so those runs genuinely cannot be compared, and merging them would show one group
whose members refuse to compare across an invisible line inside it. The honest options are a format
version stored beside the hash, or accepting that a fingerprint change obsoletes old runs and saying
so. **Both this and P-3 are one question asked twice**: a hash whose recipe is identified by the
build that read it rather than by a value stored with it. Worth settling once.

**`#17` detail — adjudicated 2026-09, and the original line was wrong.** It said the ladder treats
91 as proof of *refused protection*. It does not: `ConnectionFailureReason.Of` maps 91 to
`ProtectedChannelFailed`, which is a distinct reason and a correct one. The fault is one entry
further on. `ProvesTheControllerAnswered` lists `ProtectedChannelFailed` alongside
`CredentialsWereRejected` and `ProtectionWasRefused`, and that list is the gate `0018`'s amendment
put in front of the forest finding. So a 91 on rung 1 plus any failure on rungs 2 and 3 satisfies
the gate, and an undeclared run ends at *"a controller accepting nothing signed leaves its LDAP
traffic open to alteration in transit."* A broken LDAPS certificate on 636 plus a firewall on 389
reaches it — a certificate fault accusing a customer's forest.

**Microsoft settles it.** 0x5b is *"Cannot establish the connection"*
([Return Values](https://learn.microsoft.com/previous-versions/windows/desktop/ldap/return-values)).
That is the client failing to connect, with nothing in it about the server having responded. 49 and
8/13 are result codes a controller sent; 91 is not.

**How it survived the amendment.** The amendment has three cases and `ConnectionSecurityTests` has a
test for each — 81, 49, and unclassified. The fourth entry in the same list was carried over without
being re-asked. The `P-19` lesson again, from the other direction: *ask what the check's subject is,
not only whether it passes.*

**The remedy, so the fix pass need not re-derive it.** Drop `ProtectedChannelFailed` from
`ProvesTheControllerAnswered`. That routes an all-91 walk to the no-answer branch, whose message
currently offers name, host and firewall — true but understated for a TLS failure, so that branch
wants a third variant beside the existing `timedOut` one, saying the transport could not be
established and naming the certificate. Add the missing test.
`ConnectionFailureReason`'s comment calls 91 *"the transport could not be established - in practice,
TLS"*; the *in practice, TLS* half is inference rather than the citation, and it is what makes 91
look like an answer. Recorded in [`_DRIFT.md`](_DRIFT.md).

**`#20` detail.** The deep review says link order 1 is highest precedence and warns against
`Count - Order + 1`. S-58 lists that same expression under *what must not change*, saying the last
GPO in the sequence has the highest precedence. Neither cites a specific Microsoft page. **Settle
against Microsoft; do not prefer the later document.**

**`#21` carries a durable point** beyond the parser itself: prefer `objectGUID` or `objectSid` over
DN-string equality for cross-source identity. That is what `#18` got wrong when joining SYSVOL
evidence to directory objects.

---

## Deferred features

| Item | Where |
|---|---|
| Effective access evaluation — layers 3 and 4, requirements R8, R10, R11, R12, R16, R20 | [`planned/effective-access.md`](planned/effective-access.md) |

---

## Closed

Findings checked against the code and confirmed already fixed are **not listed here**. Git history and
the archive hold them, and repeating them made this file longer than the documentation it supports.

Two exceptions, because they are easy to mistake for gaps on a future sweep:

- **`#14` was refuted, not fixed.** `MembersOfPropertySet` returning a nullable list already
  distinguishes *empty* from *unknown*. Do not reopen.
- **R9 and R18 are implemented but uncited.** `searchFlags`/`systemFlags` capture answers R9;
  `WellKnownSidRole` answers R18. A citation in the layer doc would stop every future sweep
  rediscovering them.
