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
| P-20 | `F-S44-2` — the catalogue's three test suites are a closed loop anchored to the rules already written, and it has no external anchor | open | a reconciliation fixture naming every predecessor attribute or a written omission |
| P-21 | `0065` is decided and unimplemented; every run taken before it lands is permanently silent on the trust attributes | open | — |
| P-22 | `F-S40-1` — `0040` decided a failed domain is read again from another controller, and nothing walks that path | open | — |
| P-23 | Gate 5b is recorded as blocked on an entry point that now exists (`CaptureRun`) | decision | whether to turn it on |
| P-24 | `F-S23-4` — six captured attributes have no consumer among the sixty-two rules; three are named attack surfaces the product holds data for and says nothing about | open | rules at branch E |
| P-25 | `F-S23-5` — six rules need SYSVOL and nothing in the directory answers them; ten per cent of the catalogue is inert and nothing says so | open | B14/B15 |
| P-26 | `F-S7-37`, `F-S7-39`, `F-S7-40` — three claims about how a real controller behaves that no test in this repository can settle | blocked | lab session |

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
| P-27 | The surface register misstates F6 and F17 against the code — S-18's *What is owed* was checked and two of its three claims are false | evidence/run library | open |
| P-29 | `RunComparability` is written and nothing calls it — the run library, drift summary, compare window, acceptance import and baseline marking are the five doors owed | evidence/run library | open |
| P-30 | A point-in-time review is owed: what the product does today, each accepted decision in one line, and where earlier decisions have been overtaken | documentation | decision |
| P-31 | Three Evidence layer documents carry no capability table, and the ten that exist elsewhere are bound by nothing | evidence · documentation | decision |
| F-0056-1 | No pre-capture total of unestablished facts exists | evidence/coverage | open |
| P-18 | `CaptureRunEndToEndTests` fails intermittently on a disposed SQLite handle | tests | open |

**P-31 detail. The first version of this entry was wrong and was corrected before the next sitting
read it.** It said the Evidence area files could not be trimmed until the capability tables moved.
They are not trimmed at all: AreaFileGateTests.EveryAreaFileCarriesTheThreeSections required every
area file to keep *What is decided*, *What is built* and *What has not been discussed*, and
`LabConfirmationColumnTests.EveryBuiltTableCarriesTheLabColumn` enforces the lab column on the same
table. **The cycle's *carry the capability table across* is a copy, not a move.** The claim was
written from the cycle text without reading the gate that governs it. *The first of those two gates
was deleted on 2026-08-21 (`P-51`), which is what unblocks the trimming — see `P-57`.*

The deletions are complete — `S-16` and `S-18` are gone, and every surviving mention of either is a
deliberate historical citation inside a block quote.

What is actually open is two questions, and the second is larger than the first.

- **Three Evidence layer documents carry no capability table**: `the-bundle-on-disk.md`,
  `run-identity-and-coverage.md`, `whether-two-runs-compare.md`. Only `what-a-bundle-holds.md` does.
  Ten of the twelve layer documents in `kernel`, `audit` and `connect` do; `permission-requirements.md`
  and `how-a-connection-is-opened.md` are the other two that do not.
- **Nothing binds a layer document's capability table.** `AreaFileGateTests` and
  `LabConfirmationColumnTests` both scan `docs/areas` only, and the per-document gates bind types,
  members and marker tables — not capability rows. So the ten tables that do exist name test methods
  that no check resolves. A test renamed out from under one of them fails nothing, which is `P-19`'s
  shape and the precise failure `PunchListIdentifierTests` was written for one file over.

**Adding three more unbound tables would make the problem bigger, so this is a decision and not a
chore.** Either bind them — one gate resolving every capability citation in the layer documents
against the test assembly, which `AreaFileGateTests` already has the code for — or decide the layer
should cite the area file instead of restating it, and correct the cycle text in `_HANDOFF.md`. The
ten existing tables settle nothing on their own, because unbound is how they all got there.

> **RULED, fourth Evidence sitting: bind them.** `CapabilityCitationTests` now resolves every
> capability citation in `docs/layers/kernel`, `docs/layers/audit`, `docs/layers/connect` and `docs/layers/evidence` against the
> test assembly, reusing the resolver `AreaFileGateTests` already had — which is now shared as
> `TestCitation` so the two cannot drift apart. Citing the area file was rejected: it would send a
> reader back to the split the rewrite exists to remove, and move evidence out of the page he is
> actually on.
>
> **The decision was settled by evidence, not by argument.** Scanning the ten tables before ruling
> found the rot had already happened: `the-attribute-catalogue.md` cited two methods under the names
> EveryAttributeTheCodeRequestsIsInTheDocument and TheDocumentNamesNoAttributeTheCodeDoesNotRequest —
> written here without backticks, because they are history and no longer resolve — after both had been
> renamed to `TheDocumentDescribesEveryAttributeTheCatalogueRequests` and
> `TheDocumentDescribesNoAttributeTheCatalogueDoesNotRequest`. Two of 170 citations, dead, for as long
> as the rename is old. Corrected at source, and the gate was proven by reintroducing one and watching
> it go red naming the file and line.
>
> **Two corrections to the count above, both found by reading rather than by counting the prose.**
> The ten are not *ten of twelve in kernel, audit and connect carrying `## What is built`* — the three
> kernel documents write the same three-column table under **`## What an operator can do`**. A gate
> keyed on one heading would have passed while silently scanning nothing in kernel, which is `P-19`
> for the sixth time and was nearly committed. `CapabilityCitationTests` matches both openers and its
> self-test asserts each subsystem was reached rather than that some global count was above zero.
>
> **And `P-31`'s own correction is still not quite right.** EveryAreaFileCarriesTheThreeSections
> requires the *heading*, not the rows beneath it. The rows are held only in aggregate — by
> `LabConfirmationColumnTests.TheCheckReadsTheBuiltTables` at ten files or more, and by
> `AreaFileGateTests` requiring some capability somewhere — so any *single* area file could still be
> emptied without anything going red. The conclusion *carrying the table across is a copy, not a move*
> survives; the reason given for it was one gate too shallow. Third instance of **read the rule, then
> read the code that enforces it**, and the first where the mis-read sentence was itself a correction.

- `P-32` — **`RunLibrary.DeleteRun` has no direct test.** Deletion is exercised through
  `RunLibraryViewModelTests` against a fake catalogue, so the library method's own behaviour — the
  `RunIsNotThere` refusal, the `RunCouldNotBeDeleted` path that leaves the run listed, and the fact
  that everything including `annotations.db` goes — is asserted nowhere. Found while writing
  [`how-a-bundle-is-read.md`](layers/evidence/how-a-bundle-is-read.md) and recorded there. Documentation
  pass, so recorded rather than fixed.

- `P-33` — **Nothing validates the lab column in a layer document.**
  `LabConfirmationColumnTests` scans `docs/areas` only, so the *Confirmed in lab* column on the
  eleven layer-document capability tables is unchecked in both directions: a table could lose the
  column and stop asking the question, or carry a word instead of a date, and nothing would go red.
  `CapabilityCitationTests` was deliberately kept to citations because that is what its name says,
  and this was left rather than folded into it. The scanning is already shared in shape — both
  gates walk the same three-column table under two possible headings — so the fix is to widen
  `LabConfirmationColumnTests` to the layer documents rather than to write a third scanner.

- `P-34` — **CLOSED. Step 7 of the cycle had no gate, and now has two.** Deleting the consumed
  documents and correcting the solution items was the only step of the rewrite cycle nothing
  enforced: a pass that skipped it committed green, and did, twice.

  **The obvious remedy was rejected.** Asserting that each consumed document is *absent* needs a
  hand-written list of what should be gone. Nothing generates that list, nothing else consumes it,
  and forgetting an entry makes the check **pass** — it rots toward silence, which is the worst
  direction. `check-instruction-claims.ps1` is the only absence check here that works, and it works
  because the instructions themselves name the symbols; a deletion list has no such anchor.

  So the **consequence** is checked rather than the act. `LayerDocumentGateTests` holds that every
  link out of a layer document resolves — a document deleted without its inbound references
  repointed leaves a link to nothing — and that every layer document is listed in the solution.
  Neither needs a list, and the first catches a broken link arriving from any other cause for free.
  `AreaFileGateTests` has done the same for `docs/areas` since the beginning; the pages the rewrite
  actually produces had nothing. Both proven red before being accepted.

  **`SolutionDocumentItemTests` said the opposite and has been amended.** Its remarks argued the
  reverse direction was deliberately unchecked because an unlisted document *harms nobody*. True of
  `docs/decisions` and its scores of records; false of the seventeen layer documents, where the
  omission is a recorded defect. The general rule stands and the narrow exception is now written in
  both files rather than left as a disagreement between a gate and the cycle text.

**Where S-18's findings went.** `S-18` was deleted when
[`run-identity-and-coverage.md`](layers/evidence/run-identity-and-coverage.md) and
[`whether-two-runs-compare.md`](layers/evidence/whether-two-runs-compare.md) consumed it. All five of its
findings read REPAIRED and were checked: four are held by git and are not repeated here, and
`F-S18-5`'s substance — *do not remove the factory guard on the strength of the redundant one* — is a
do-not-change rule and moved into the layer document. **`F-S18-4`'s residual claim that a test
binding the decisions index was owed is false**; `EveryDecisionRecordAppearsInTheIndex` exists and
was written after that section. That is the second time in two sittings that an unbuilt-work claim
in `S-18` did not survive being read against the code. Only `P-29` and `P-30` came out of it live.

**P-18 detail.**
`System.ObjectDisposedException: SQLitePCL.sqlite3`, then passed in isolation and on two subsequent
runs. Low severity but it corrodes the oracle: *"A test that fails at random trains a reader to
re-run rather than to look, and the day it fails for a real reason it will be re-run too."*

**`#17` detail — adjudicated 2026-08, and the original line was wrong.** It said the ladder treats
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

## Kernel / Schema

| ID | Item | Status | Blocked on |
|---|---|---|---|
| P-35 | `SchemaGuidCatalog.Version` is recorded in no bundle, so a bundle written before the eleven Microsoft corrections and one written after are indistinguishable and the older one's names cannot be known to be wrong. `BundleReader.Open` already refuses a `canonicalization_version` mismatch; this has no equivalent | open | — |
| P-36 | A shipped and a captured name disagreeing about a base-schema GUID is a finding per `0014`, and nothing computes it. `SchemaGuidCatalog.CapturedOver` resolves the display question and is where the evidence would come from | open | — |
| P-37 | `CapturedSchemaGuidReader` is documented in no layer. It is Evidence's by the one-document-per-code-folder rule, and Evidence closed at five documents without covering it | open | a further Evidence sitting |
| P-38 | Only the Capture project has an assembly-wide *is every public type documented* gate. `CapturedAttributeCatalogDocumentationTests` carries it; nothing equivalent covers `SecureAD.Evidence`, `SecureAD.Kernel` or the rest. Every other check is `TheDocumentNamesEveryPublicTypeInTheComponent`, scoped to a component a document already claims, so a type no document claims is checked by nothing. This is why `SecureAD.Evidence/Findings/` reached 0 of 17 types documented with the suite green | open | — |

---

## Kernel / Naming

| ID | Item | Status | Blocked on |
|---|---|---|---|
| P-39 | DN comparison has no owner. There is no member deciding whether two DNs are the same or whether one contains another, so callers write it out. A containment test written as *the child ends with the parent* answers yes for a suffix that is not a DN, which attributes an object to a container that does not exist | decision | which comparison: ordinal over the whole string, or component-wise with a parse |
| P-40 | The quoted form of an RDN value is not understood — only the escaped form. A quoted value is cut at the comma inside the quotes. Pinned by `WhenAValueIsQuotedRatherThanEscaped_ThenTheQuotingIsNotUnderstood`, which asserts the wrong answer on purpose and is to be rewritten rather than deleted | open | — |
Pinned by `WhenAValueEndsInAnEscapedBackslash_ThenTheFollowingSeparatorIsMissed` | open | — |
| P-42 | `ExtractFirstRdn`, `ExtractFirstRdnOrNull` and `ExtractNameFromDn` differ only in what absent input returns. The distinction between `null` and empty is real, so this is not duplication, but the third could be a caller-supplied fallback. Cheaper to settle now than once more call sites exist | decision | owner ruling |

---

## Documentation rewrite

Blockers to the consolidation itself. `D-1` — the register forbidding any area file to be deleted —
was fixed and discharged; the first four area files went with it.

**How close each area file is to deletion, measured 2026-08-21** — types it governs in
`SURFACE-REGISTER.md`, and how many of those no layer document names yet. `P-52` fails the build
when a right-hand column reaches zero. Six of the sixteen area files have no register rows and are
absent here; see `P-56`.

| Area file | Governs | Still undocumented |
|---|---|---|
| `what-a-permission-means` | 24 | 3 |
| `the-new-audit-wizard` | 7 | 3 |
| `how-failures-are-reported` | 7 | 3 |
| `what-we-capture` | 31 | 3 |
| `the-run-library` | 11 | 5 |
| `group-policy` | 23 | 6 |
| `how-results-are-shown` | 8 | 8 |
| `how-a-run-is-stored` | 17 | 12 |
| `which-controller-we-read` | 36 | 13 |
| `what-we-call-a-finding` | 15 | 15 |

| ID | Item | Status | Blocked on |
|---|---|---|---|
| P-51 | AreaFileGateTests.EveryAreaFileCarriesTheThreeSections and GroupPolicyDocumentationTests.EachDocumentCarriesACapabilityTable were prose-shape tests: no change to the product could make either fail. The first forced three headings into every area file, so a file could not be shrunk toward nothing, only deleted whole. **Both deleted 2026-08-21**; the generative checks and scanner self-tests in both classes stayed | done | — |
| P-52 | `AreaFileGateTests.EveryAreaFileStillGovernsAtLeastOneUndocumentedType` **added 2026-08-21**. An area file's types are its rows in `SURFACE-REGISTER.md`, which is already held to the exported types of the three production assemblies in both directions; a file whose every type is named by a layer document fails. Proved failing by documenting the last three types of `how-failures-are-reported` in a layer document: it failed naming that file and all seven types it governs. Register parsing moved into a shared `SurfaceRegister` so one table has one parser | done | — |
| P-53 | Measured 2026-08-21, and **neither hypothesis was right**. `how-the-app-looks.md` has no register rows because the shell exports **zero public types** — `ShellSurfaceGateTests.TheShellProjectExportsNothing` holds it to that, and `SURFACE-REGISTER.md` §*The register* already records the shell as out of its scope. The register is not missing UI types; there are none to miss. The file is 266 lines with 75 backticked citations, describing internal view models and screens | done | — |
| P-56 | `P-52` cannot reach the six area files with no register rows, `how-the-app-looks.md` among them. A public-type register cannot cover a shell that exports nothing by design, so nothing will ever say when that file is fully consumed. It needs a device anchored to the shell's internal types or its XAML views, not to the register | open | — |
| P-57 | Capability tables duplicated between an area file and a layer document were copies because a gate forbade emptying the area file's *What is built* section. `P-51` removed that gate, so each duplicate can now be **moved**: delete the rows from the area file in the same turn. Known instance: `what-a-schema-guid-means.md` and `what-a-permission-means.md`. Check `LabConfirmationColumnTests` before trimming — it counts built tables in aggregate | open | — |
| P-58 | **37 doc-comment citations in 30 source files named documents that were not there**, and the suite was green throughout. Thirty were the second form of the `docs/` → `docs/layers/` move — the path written whole in a comment, where the move searched for it split across `Path.Combine` arguments. Seven named documents deleted outright. **Fixed 2026-08-21** and `DocumentPathCitationTests.EveryDocumentPathCitedInCodeResolves` added, which fails on any path a code tag encloses that does not resolve. A path in plain prose is history, matching the backtick convention `PunchListIdentifierTests` uses for identifiers | done | — |
| P-54 | Only the Capture project has an assembly-wide "every public type is named by some document" gate. Every other documentation gate is scoped to the component a document already claims, so it can only check types somebody chose to describe. `GroupPolicyDocumentationTests` has the stronger shape; widen the rest, highest in-scope debt first (`Evidence/` root, 14 of 44) | open | — |
| P-55 | `_COVERAGE.md` is stale. The Kernel/GroupPolicy pass read 1,273 source lines, 1,259 test lines and an 86-line area file and recorded none of it | open | — |

**Out of scope, not debt:** findings and rules — `docs/rules/` (67 files, 15,590 lines),
`SecureAD.Evidence/Findings/`, and the area files `what-we-call-a-finding.md` and
`accepting-a-finding.md`. Documented when the feature is implemented. Also `domains-we-skip.md`,
`how-privilege-escalates.md` and `reports-and-export.md`, which are **specifications for unbuilt
features**, not documentation debt — they govern no types because there is no code yet.

---

## Kernel / GroupPolicy

| ID | Item | Status | Blocked on |
|---|---|---|---|
| P-43 | `docs/areas/group-policy.md` is consumed for its 16 Kernel types but still governs 7 more — `ISysvolFileReader`, `SmbSysvolFileReader`, `GpoTarget`, `GpoInventory`, `SysvolCapture` in Audit and `GpoSettingScope`, `RestrictedGroupRelationship` in Evidence. The area file is deleted, and its 23 `SURFACE-REGISTER` rows repointed, once those are documented. Until then the rewrite has added two documents without removing a file | open | an Audit/SYSVOL pass and two Evidence types |
| P-44 | EachDocumentCarriesACapabilityTable in `GroupPolicyDocumentationTests` asserts only that a heading exists, so it passed when pointed at a document that carries none of the subject. Every other check in that gate failed as it should. A check that cannot fail for the reason it was written is decoration. **Discharged by `P-51`, which deleted it 2026-08-21** | done | — |
| P-45 | The solution lists four kernel documents twice, once under the `next` folder and once under `decisions`, and the second copy is missing `distinguished-names.md`. `LayerDocumentGateTests` reads the union of all items so it cannot see either fault | open | — |
| P-46 | What the product judges about a policy, as opposed to what it reads. The parsers exist; the rules that read them are largely unwritten and which questions matter is unsettled | decision | owner ruling |
| P-47 | Whether a policy's effect is worked out — which objects it reaches through links, blocked inheritance, enforcement and security filtering — or whether the product reports the link and stops | decision | owner ruling |
| P-48 | How a policy that is linked but disabled is treated. The link option bits are carried as stored and deliberately not worded, so nothing currently reads *disabled* | decision | owner ruling |
| P-49 | Whether SYSVOL file permissions are judged as permissions, on the same footing as directory permissions, or reported separately | decision | owner ruling |
| P-50 | What happens when the directory and SYSVOL disagree — a policy container with no folder, or a folder with no container | decision | owner ruling |

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
