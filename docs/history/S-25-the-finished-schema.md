# S-25 — The finished schema

Ledger row **C1**, taken from *Decided, rebuilding after review* to **Done**.

## What it does

`BundleSchema` creates every table a bundle contains and `BundleWriter` fills them. `S-24` rebuilt
the object half of that file and left the security-descriptor half as it was, so the file held
current and superseded work side by side with nothing marking the boundary. This session built the
descriptor half, the six C1 instructions never built, the three findings `S-24` raised and did not
repair, and the one decision made after `S-24` began.

The build was red on one check when this session started — `UnvouchedResultGateTests` fired on
`EvidenceObject.Attributes`, deliberately left failing by `S-24` as a visible debt. It is green.

## Shape

**Descriptors are stored once.** `security_descriptor` is keyed on the SHA-256 of the bytes the
controller sent, with the byte length and the raw bytes beside it. `ace` and
`security_descriptor_error` hang off the descriptor rather than the object, and
`object_security_descriptor` records which objects were read with which. A forest holds a few
thousand distinct descriptors repeated across millions of objects, so this is the difference C1
measured: 4.81 GB down to 1.24 GB per 100,000 objects, and about three quarters of the parsing and
inserting removed with it.

**Three states where there was one.** An object with no entries can mean it grants nothing, that its
descriptor could not be parsed, or that its descriptor could not be read at all. The third now has a
row of its own, and `ace_count` stays null for it rather than becoming zero.

**Coverage is one type.** `PartitionCoverage` and `PartitionCoverageRecord` were twins with
identical fields in two projects. They are one type in `SecureAD.Evidence` per
[`0035`](../decisions/0035-coverage-is-recorded-once-per-capture-unit.md), carrying the connection
security level the partition was read over. The configuration and schema partitions gained a
run-level home that is not domain-shaped.

**The object carries its partition.** `EvidenceObject` holds the `PartitionCoverage` it was read
under and `WriteObject` no longer takes a separate handle, so the two cannot disagree.

## Dependencies

- **Depends on:** `SecureAD.Kernel` for the attribute catalogue, the canonical ACE pipeline and
  `DnHelper`.
- **Depended on by:** nothing yet. The capture-to-bundle seam (**B9**, **B10**, **C15**) is the row
  that will call this, and it is the next session.
- **Layering violations:** none. Two enums moved *down* into `SecureAD.Evidence`; nothing moved up.

## Verified-safe

- **The descriptor hash is cryptographic.** `SHA256.HashData` over the bytes as they arrived, with
  the byte length stored beside it. A collision here would not corrupt a row — it would give one
  object another object's permissions.
- **The misattribution guard survived the rewrite.** A descriptor whose own view of which object it
  belongs to disagrees with the object it is written against still ends the run. Deduplication made
  this easier to get wrong, not harder, because one descriptor row is now reached by many objects;
  the guard is on the write call rather than on the row, so it still fires per object.
- **Both new set-based passes run after the deferred indexes exist.** Each joins on a column the
  indexes create. Run before, each would be a scan per row.
- **Every new guard was mutation-tested in both directions**, listed under *Mutation testing* below.

## Findings

### F-S25-1 — `page_size` is silently ignored after write-ahead logging, not only after the first table

- **Severity:** correctness-risk
- **Confidence:** verified by mutation
- **Evidence:** C1 says `page_size` "cannot be changed after the first table exists". That is true
  and incomplete. Moving `Pragma(connection, "page_size = 8192")` to sit *after*
  `journal_mode = WAL` and before `CreateTables` — so the first table still did not exist — left the
  page size at 4096, and `ThePageSizeIsSetBeforeTheFirstTableExists` failed. SQLite refuses the
  change once the database is in write-ahead logging mode, and reports no error for it.
- **What happens to a user:** a bundle whose descriptors overflow onto twice as many pages as
  intended, with a line in the source that reads as if it configured otherwise.
- **Why it matters beyond this row:** it is a pragma that fails by doing nothing. Nothing in the
  provider surfaces it, so the only defence is a test that reads the value back off a real file,
  which is why one exists rather than a comment.
- **Status:** REPAIRED — 2026-08-13. `page_size` is the first pragma set, before `journal_mode`, and
  the ordering carries a comment saying why.

### F-S25-2 — C1's account of the predecessor's `reason_category` is right about the defect and wrong about its cause

- **Severity:** documentation
- **Confidence:** verified
- **Evidence:** C1 says the predecessor's constrained set "defaulted to `'Undetermined'` and a
  constrained set that does not constrain is not one". Reading
  `DirectGroupMemberWriter.cs:14-37`, `Undetermined` is a reasoned member — *"the forest's domain
  list is not known for this run, so no claim is made"* — and `Classify` sets it deliberately for the
  re-analysis case. The defect is that it was reachable **by omission at two independent layers**:
  the C# record's default parameter (`Category = UnresolvedMemberCategory.Undetermined`) and the SQL
  column default (`DEFAULT 'Undetermined'`). Anything that forgot to classify silently claimed to
  have no opinion.
- **Why this matters for what was built:** the two accounts imply different repairs. "The category
  is useless" implies removing it; "the category is reachable by accident" implies keeping it and
  removing the defaults. `unresolved_reference` has no default and no fallback member.
- **A second thing the predecessor was right about.** It carried a prose `reason` *and* the typed
  category, and its comment records why: deriving behaviour from the prose *"made the message text a
  load-bearing contract, so rewording it silently changed a metric and a UI column"*. C1's "no free
  text beside it" is the right call, but what the prose also carried was *which* domain — and that is
  data, not explanation. It is stored as the `reference` column.
- **Status:** RECORDED — 2026-08-13. Built to the corrected reading.

### F-S25-3 — `0022`'s closed four have no "cannot be determined", and that is correct for a reason neither document states

- **Severity:** documentation
- **Confidence:** verified
- **Evidence:** [`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md) names four
  reasons: in a domain that was not captured, in another forest, an orphaned identifier, or
  unreadable. The predecessor's equivalent had a fifth — the state where the forest's domain list is
  unknown, so neither *in-forest* nor *cross-forest* can be claimed.
- **Why the four are sufficient:** that state only arises during re-analysis of a saved capture, and
  [`S-15`](S-15-storage-dispositions.md) removed re-analysis from the rebuild. Every bundle is now
  written by the run that read the forest, so the domain list is always known.
- **Why it is worth writing down:** the next reader to meet `0022`'s four will ask what happens when
  the answer is unknown, and the reason it cannot be is two documents away. It is recorded in
  `UnresolvedReferenceReason`'s own remarks so the answer sits where the question is asked.
- **Status:** RECORDED — 2026-08-13.

### F-S25-4 — The silent skip `F-S20-4` names exists in two writers, not one

- **Severity:** correctness-risk, in the predecessor only
- **Confidence:** verified
- **Evidence:** `F-S20-4` cites `DirectObjectWriter.cs:126` — `if (objectGuid is null) return;`. The
  same pattern is at `DirectAceWriter.cs:138`, and beside it at line 141 is
  `if (sdBytes is null || sdBytes.Length == 0) return;` — the unreadable-descriptor case. The file's
  only counter, `_totalSdsProcessed++`, is at line 191, *below both returns*, so it counts successes
  only. There is no number anywhere in the predecessor for the 19,927 objects of `F-S20-16`: they are
  not undercounted, they are uncounted.
- **A third instance in the same file:** `TryWriteMaterializedAcl` (line 260) catches every exception
  and writes to `Debug.WriteLine`, which is compiled out of a release build.
- **What happens to a user:** the one `F-S20-16` already describes, with the mechanism named.
- **Why it is recorded here:** this row is done and the predecessor is not being fixed. It is
  evidence that the pattern was a habit rather than an oversight, which matters to whoever ports the
  remaining writers.
- **Status:** RECORDED — 2026-08-13. Not acted on; the rebuild's equivalent is a positive row.

### F-S25-5 — The documentation disagreement is wider than this row, and is not fixed here

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** binding tests caught five documents disagreeing with the code during this session
  alone — `S-16`, `S-18`, `S-2`, `SURFACE-REGISTER.md` and the README warning box. Each was repaired
  because a test failed. That is the mechanism working, and it is also the limit of it: only
  documents with a binding test are covered, and `F-S24-2` already showed that a binding between a
  document and the code cannot detect that *both* describe a superseded design.
- **What happens to a user:** nothing directly. The exposure is to the next session, which is what
  `S-24` demonstrated by building from `S-16` and `0022` without opening the row that owned the work.
- **Options:** a session that reads every document in `docs/next/` against the code and the accepted
  decisions, and either corrects or supersedes each; or continuing to repair on failure.
- **Decision:** the owner asked for the sweep on 2026-08-13 and it is **owed as its own session**,
  not absorbed here. This row was already carrying ten items and `S-24`'s failure mode was being
  individually justified at every step and finishing nothing.
- **Status:** OPEN — 2026-08-13. Decided, unstarted.

### F-S25-6 — Two enums moved projects, which no test would have caught

- **Severity:** low
- **Confidence:** verified
- **Evidence:** `NamingContextKind` and `ConnectionSecurityLevel` moved from `SecureAD.Audit` to
  `SecureAD.Evidence`, because a single coverage type in the evidence project cannot name types that
  live above it. `SurfaceRegisterTests` matches on the short type name and `RebuildAssemblies` names
  the audit assembly through `LdapEntryReader`, so neither noticed — correctly, since neither is
  about where a type lives, but it means the register's *Assembly* column is unchecked and can rot.
- **Why the move rather than a string:** the alternative was storing the kind as text, which is what
  the discarded twin did. `0035` exists because two coverage definitions drifted, and a stringly seam
  is how the next one would.
- **Status:** RECORDED — 2026-08-13. Register updated by hand; the column remains unenforced.

## Mutation testing

Every new guard, mutated and reverted. Both directions observed for each: the listed tests fail with
the mutation applied, and the whole suite passes without it.

| Mutation | Tests that fired |
|---|---|
| Deduplication lookup removed, so every descriptor is inserted afresh | `TwoObjectsSharingADescriptorStoreOneDescriptorAndOneEntrySet`, `ATrusteeAppearingOnManyObjectsIsStoredOnce`, `TwoObjectsWithTheSameEntriesShareASetHashAndOneWithADifferentEntryDoesNot` |
| `ace_count` set to zero rather than left null where no descriptor was read | `AnObjectWhoseDescriptorCouldNotBeReadIsDistinguishableFromOneThatGrantsNothing` |
| `page_size` set after `journal_mode = WAL` instead of before | `ThePageSizeIsSetBeforeTheFirstTableExists` — see `F-S25-1` |
| Forest-wide partition reported zero times accepted instead of refused | `AForestPartitionWithNoOutcomeIsRefused` (both theory cases) |
| Per-partition unreadable-descriptor tally never incremented | `UnreadableDescriptorsAreCountedAgainstThePartitionTheyWereReadFrom` |
| Uncaptured parent not recorded as an unresolved reference | `AContainerThatWasNeverCapturedIsRecordedAsAnUnresolvedReference` |

One guard was found to have **no** test while doing this — the writer's refusal of an object whose
partition was never recorded. `AnObjectWhosePartitionWasNeverRecordedIsRefused` was added.

## What was got wrong

**A bulk regular expression was used to edit test files across four paths at once.** It happened to
produce the right result in the two files it changed and to leave the other two alone, but that was
luck: the pattern matched `]);` followed by a blank line and an `Assert`, which is not a shape unique
to the call being changed. The remaining call sites were done explicitly.

**A failed command wrote a stray file into `next/`.** `[IO.File]::ReadAllText` threw on a relative
path, and the subsequent `WriteAllText` in the same command ran anyway — writing the contents of a
variable left over from an *earlier* tool call, because the shell session persists between them.
`GreenfieldGateTests.EverySourceFileBelongsToAProjectInTheSolution` caught it. The gate did exactly
what it exists for.

**The C1 ledger row was truncated by an editing tool and restored from git.** A replacement whose
matched span ended mid-line dropped everything after it — several thousand words of reasoning — even
though the replacement text ended at the same point. It was restored with
`git checkout HEAD -- docs/next/WHAT-THE-OLD-APP-HAD.md` and redone with a script that asserts the row's
length before and after. **That file's rows are single lines of six to eight thousand characters and
should not be edited with a string-replacement tool.**

## Not built, and why

- **The capture-to-bundle seam** (**B9**, **B10**, **C15**). `WriteObject` and
  `WriteSecurityDescriptor` changed shape here and nothing calls them yet. That is the next session
  and this one was told not to absorb it.
- **`CapturedObject.Completeness`** (`F-S24-9`), which belongs with that seam.
- **`F-S24-1` option B** — making sealing the automatic rung — which is ledger row **A2**'s.
- **`F-S20-15`**, the suppression of expected grants, owed to **D7** by the decision to store
  inherited entries.
- **The documentation sweep**, `F-S25-5`.
