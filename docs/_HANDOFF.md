# Handoff: the documentation rewrite

**Read this first in a new session.** It replaces reconstructing the plan from conversation.

---

## The goal

Replace the sprawling documentation — 120+ files across `docs/areas`, `docs/next` and
`docs/decisions` — with one document per code folder, written from the code, bound by the existing
gates, with the old documents deleted as they are consumed.

**This is a documentation rewrite, not a product audit.** Gaps found along the way are recorded in
[`PUNCH-LIST.md`](PUNCH-LIST.md) and left alone. Fixing them is separate work.

---

## State

**Done — Kernel/Security.** Commit `f1d49f6`. Four documents in `docs/kernel/`, three slice documents
deleted (1,632 lines), all gates retargeted, 2,159 tests green.

**Done — Audit/Capture.** Commit `ee63b7f`. Four documents in `docs/audit/` — the attribute
catalogue, the search capture issues, how a controller's answer is read, and what a controller's
limits oblige. Six slice documents deleted (1,856 lines), six gate suites retargeted, one unsound
gate widened and fixed, 2,160 tests green.

**Two things about that pass are worth carrying forward.**

*The gate that widened.* `EveryPublicTypeInTheCaptureProjectIsNamedByACaptureSliceDocument` scanned
four types while its name and failure message claimed nineteen, and had been green for months. The
fault arrived **by repair**: S-24 moved the catalogue into another assembly, the check failed loudly,
and the fix pointed the scan at the catalogue's new neighbours rather than at the component the test
is named for. Widened during the pass; it immediately named twelve types no document mentioned. It
is `P-19`. **When a check fails after a move, ask what its new subject is — not only whether it
passes again.**

*The archive backlog was not read, and that is correct.* The documents were written from the code,
the tests, the slice documents bound to them and the governing area files — the complete code-first
input set. The 27 archive files under `audit-capture` belong to a **separate later pass**, described
at the top of `_COVERAGE.md`. **Audit/Capture is closed.**

The rule that previously said otherwise — *nothing is drafted until every archive file is consumed* —
was written while the rewrite was archive-first and was left stale when it became code-first. It is
retired. An unread archive backlog is work not yet started, not a defect in a finished pass.

**Why this is not `F-S44-2`.** That fault was a catalogue *reassembled* and then checked against rules
*derived from the same catalogue* — a closed circle with nothing outside it, in which wrong values
survived. A document derived from the code and checked against the code is also a circle, but the
code is the artefact that ships and the document's job is to describe it. What such a document cannot
tell you is whether the code is *right*; that is the audit, and it is deliberately a separate
exercise.

The residual exposure is real but narrow: a **refusal** argued once and never restated, which a
future session could reverse without knowing. Those are found by searching the archive for
decision-shaped language — *decided, refused, must not, rejected, instead of* — not by reading whole
files.

**Done — Audit/Connect.** Four documents in `docs/connect/` — the connection ladder, how a connection
is opened, how the forest is found, and what preflight proves. `S-14-the-connection.md` deleted
(225 lines), `ConnectionDocumentationTests` retargeted, `which-controller-we-read.md` trimmed to its
decision index, `F-S40-1` carried to the punch list.

**Punch-list `#17` was adjudicated during that pass, and the line recording it was wrong.** It said
the ladder treats LDAP 91 as proof of *refused protection*; it does not — 91 maps to
`ProtectedChannelFailed`, which is correct. The fault is that `ProvesTheControllerAnswered` counts
`ProtectedChannelFailed` as an answer, and that list is the gate `0018`'s amendment put in front of
the forest finding. A broken LDAPS certificate on 636 plus a firewall on 389 therefore reaches
*"a controller accepting nothing signed…"*. Microsoft defines 0x5b as *"Cannot establish the
connection"* — the client's own failure, not a response. **Recorded, not fixed**, with the remedy
written out; the branch stays documentation-only.

**How it survived is the transferable part.** `0018`'s amendment has three cases and there is a test
for each — 81, 49, unclassified. The fourth entry in the same list was carried over without being
re-asked. That is `P-19` from the other side: **when a rule is applied to a list, ask whether it was
applied to every entry, not whether the list still compiles.**

**Done — Evidence's bundle-and-run subject. Five documents, and the earlier claim that this closed
`SecureAD.Evidence` was wrong.** The five documents are written and bound and the *bundle* work is
finished. What the sentence *"Evidence is closed"* was then read to mean — the assembly is
documented — is false, and it was corrected during the Kernel/Schema pass by counting rather than by
recall:

| Folder | Types | Named by any layer or area document | Not named |
|---|---:|---:|---:|
| `SecureAD.Evidence/Run/` | 32 | 28 | 4 |
| `SecureAD.Evidence/` (root) | 44 | 14 | 30 |
| `SecureAD.Evidence/Findings/` | 17 | **0** | 17 |

`Run/` is genuinely closed, which is what the five documents are about. **`Findings/` is at zero of
seventeen** — `IRule`, `RuleDefinition`, `RuleVerdict`, `StoredFindings`, `EvaluatedRule`,
`FindingReader`, `Severity` and the unconstrained-delegation rules are described nowhere. The root
holds the readers — `ObjectAttributes`, `ObjectListing`, `ObjectPermissions`, `DirectoryTree`,
`EvidenceObject`, `UnresolvedReference` — and is at fourteen of forty-four.

**This is not a defect in the Evidence pass; it is a scope claim that outgrew what was measured.**
The work is unstarted, which is ordinary backlog, exactly as the archive backlog is. What was
harmful was the wording, because *closed* plus *Owed: nothing in Evidence* is precisely the
instruction a later session needs to skip the folder entirely.

**Why nothing caught it, which is the transferable part.** The Capture project has an assembly-wide
gate — `EveryPublicTypeInTheCaptureProjectIsNamedByACaptureDocument` — and it is the check that
found twelve unmentioned types when it was widened as `P-19`. **Evidence has no equivalent.** Every
other documentation gate is `TheDocumentNamesEveryPublicTypeInTheComponent`, which is scoped to the
component a document already claims, so it can only ever check types somebody already decided to
write about. A type no document claims is checked by nothing, and the gap is invisible by
construction rather than by oversight. That is `P-38`.

**One methodological note, because it nearly produced a false finding.** The first count matched
type names as ``​`Name`​`` exactly, which reads a qualified mention like ``​`BundleReader.Open`​`` as
*undocumented* and would have reported `BundleReader`, `BundleWriter` and `BundleSchema` as missing
from documents that are entirely about them. Match the identifier as a whole word inside any
backticked span. A measurement can be narrower than its own question in the same way a gate can.

*Done.* `docs/evidence/what-a-bundle-holds.md` (408 lines) — the schema, the table list, descriptor
deduplication, the three ways to produce no entries, the writing order, and what is refused against
what is recorded. `BundleDocumentationTests` and `HistoricalRecordDocumentationTests` retargeted onto
it; `docs/next/README.md` repointed; `S-16` cut from 415 lines to 111.

*Done — second sitting.* `docs/evidence/the-bundle-on-disk.md` (223 lines) — the six files a bundle
directory holds, the rename that stops a half-written one being read, the seal and its four
outcomes, and the six run states with the procedure that observes each. Bound by
`BundleOnDiskDocumentationTests`, fifteen checks, every table two-directional. **`S-16` is deleted**
(111 lines), inbound references repointed, and the solution's document items corrected in both
directions — including four `docs/kernel` documents the Kernel pass never added, which is the same
defect recorded against Evidence one subsystem later. 2,174 tests green.

**The `STATES` table moved with it, so the S-18 gate is already half split.** Run states are observed
from files on disk, so they belong beside the file names rather than beside the comparability
verdict; `RunComparabilityDocumentationTests` lost its three state checks and gained one asserting
S-18 does **not** carry a `STATES` table, so a second copy cannot come back. `RunState`,
`RunStateNames`, `RunStateObservation`, `RunStateReader`, `RunOutcome`, `RunOutcomeContents` and
`RunOutcomeFile` left its component list. **The `OUTCOMES` half is still in S-18** and moves when
`whether-two-runs-compare.md` is written.

*Done — third sitting.* `docs/evidence/run-identity-and-coverage.md` (347 lines) and
`docs/evidence/whether-two-runs-compare.md` (187 lines). Between them they take the two identities,
the four coverage records, the comparability verdict and baseline eligibility. **`S-18` is deleted**
(340 lines), `RunComparabilityDocumentationTests` retargeted onto the verdict document and narrowed
to six types, and a new `RunIdentityDocumentationTests` (347 lines) binds the coverage document with
four outcome tables. Inbound references repointed in `docs/next/README.md` and in
`ComparabilityOutcome.cs`'s own remarks. Solution items corrected in both directions. 2,215 tests
green; `check-instruction-claims.ps1` still passes.

**The retarget was proven the way this file requires.** Both new gates were pointed at the deleted
document before it went, and produced **seventeen** failures naming tables they could not find —
never an empty scan.

**`S-18`'s gate was narrower than the document it was named for, which is `P-19` for the fifth
time.** Its component list held eleven types while the prose described seventeen:
`ForestPartitionCoverage`, `SysvolCoverage`, `GpoCoverage` and their three enums were named in a
bound document and checked by nothing. Three of the four tables on the coverage page are therefore
new binding rather than moved binding.

**A gate can also be wider than its name, and that shape is new here.** `DOMAIN-OUTCOMES:BEGIN`
contains `OUTCOMES:BEGIN`, so the check asserting the coverage page carries no comparability table
failed against the page's own domain table. Both gates now match the whole comment opener. Every
previous instance of this family was a check too narrow; this one was a check too broad, and it
found itself.

**Routing S-18's findings cost nothing and confirmed the rule.** All five read REPAIRED. Four are
held by git. `F-S18-5`'s substance — *do not remove the factory guard on the strength of the
redundant one* — is a do-not-change rule and moved into the layer document. **`F-S18-4`'s residual
claim that a test binding the decisions index was owed is false**; `EveryDecisionRecordAppearsInTheIndex`
exists and postdates the section. That is the third stale unbuilt-work claim found in `S-18` across
two sittings. Only two items came out live: `P-29`, nothing calls `RunComparability`, verified
against `next/src`; and `P-30`, the point-in-time review the owner asked for.

**The session summary was wrong, and the error is worth more than the pass.** At the end of the
previous turn this session reported that `whether-two-runs-compare.md` had not been drafted when it
had, and that the solution items had been corrected when that edit had silently failed. Both claims
were fluent and confident. **The repository was left in exactly the half-done state that looks
finished** — `S-18` deleted, the solution still listing it, two new documents invisible to the IDE.
The rule already in this file caught it on the next turn only because the directory was read instead
of recalled. `replace_string_in_file` cannot reach `next/SecureAD.Next.sln`; use
`[System.IO.File]::ReadAllLines` with an **absolute** path, because the .NET APIs do not follow
PowerShell's location.

*Done — fourth sitting.* `docs/evidence/how-a-bundle-is-read.md` — the managed root, the single door
every caller-supplied identifier passes through, how a listing is assembled and why its order is a
chronological claim, why completion is read outside `BundleReader`, and why an unrecognised state
name is never a default. `RunLibrary` (378), `RunStateNames` (92) and `RunCompletionReader` (73) were
read whole, as were `RunStateReader` (150) and `RunListing` (51). Bound by
`RunLibraryDocumentationTests` — ten checks, three tables two-directional, plus a check that this
test's own hand-written refusal list still matches `RunLibrary.cs`, because a sound check pointed at
a stale list measures nothing. It carries no `STATES` table and a gate holds that open.
**Evidence is closed at five documents.**

**`P-31` is ruled: bind them.** `CapabilityCitationTests` resolves every capability citation in the
layer documents against the test assembly, and `TestCitation` is now shared with `AreaFileGateTests`
so one resolver serves both. The ruling was settled by evidence rather than by argument — scanning
the ten tables first found two citations already dead from a rename, which is the do-nothing branch
refuting itself. Full reasoning, and two corrections to `P-31`'s own wording, are in the punch list.

**The heading is not uniform, and that nearly shipped as `P-19` again.** Kernel writes the capability
table under `## What an operator can do`; audit, connect and evidence write it under
`## What is built`. A gate keyed on one opener would have passed while scanning nothing in three
kernel documents. Found by listing the headings instead of trusting the count, which is the only
reason the self-test asserts per subsystem rather than a global total.

*Owed.* Nothing in the bundle-and-run subject. `SecureAD.Evidence/Findings/` (17 types, none
documented) and most of the assembly root are unstarted, per the table above — not owed by the
Evidence pass, but not to be mistaken for finished either.

**Two gates were added after the pass closed, and they change how the cycle is checked.**

*`CapabilityCitationTests`* resolves every capability citation in `docs/kernel`, `docs/audit`,
`docs/connect` and `docs/evidence` against the test assembly. It matches **both** table openers —
kernel writes the capability table under `## What an operator can do`, the rest under
`## What is built` — because a gate keyed on one would have gone green while scanning nothing in
three kernel documents. Its self-test asserts each subsystem was reached rather than a global count
above zero. `TestCitation` is shared with `AreaFileGateTests` so one resolver serves both.

*`LayerDocumentGateTests`* closes step 7, which was the only step of the cycle no gate covered and
was skipped twice without anything going red. **The obvious remedy was rejected and the reasoning is
the reusable part:** asserting each consumed document is *absent* needs a hand-written list of what
should be gone, nothing generates it, and forgetting an entry makes the check pass — it rots toward
silence. `check-instruction-claims.ps1` works as an absence check only because the instructions
themselves name the symbols; a deletion list has no such anchor. So the **consequence** is checked
instead: every link out of a layer document resolves, and every layer document is listed in the
solution. `SolutionDocumentItemTests` argued the second of those was deliberately unchecked; its
remarks are amended, because that argument holds for `docs/decisions` and not for seventeen layer
documents.

**The weakness that remains is named in the code.** `LayerDocuments.Subsystems` is a hand-written
list of four directories. **Add Kernel/Schema to it when the pass starts**, or the new document is
silently unchecked by the link gate, the solution gate and the capability gate at once. That is the
same rot-toward-silence shape rejected above, surviving in a smaller place, and it is written into
the type's remarks as a deliberate trade.

**The deletions are complete. `P-31` is what is not, and the first version of `P-31` was itself
wrong.** `S-16` and `S-18` are gone and every surviving mention of either is a deliberate historical
citation in a block quote. `P-31` was then recorded as *the area files cannot be trimmed until the
capability tables move* — false, and written from the cycle text without reading the gate that
governs it. `AreaFileGateTests.EveryAreaFileCarriesTheThreeSections` requires every area file to keep
its *What is built* table permanently, so **carry the capability table across is a copy, not a move.**

What is genuinely open is larger and is a decision. Three Evidence layer documents carry no
capability table, and **nothing binds the ten that do exist** — `AreaFileGateTests` and
`LabConfirmationColumnTests` scan `docs/areas` only, and the per-document gates bind types, members
and marker tables rather than capability rows. So ten layer documents name test methods that no check
resolves. Adding three more would enlarge that, which is why the next sitting decides between binding
them all with one gate and having layer documents cite the area file instead of restating it.

**Both false claims in this pass have the same shape**, and it is worth stating once: a rule was read,
the code that enforces it was not, and the consequence was written as though it followed. The
correction each time came from reading the gate rather than the guidance.

**Six punch-list items were closed in the second sitting, and three of them were code.** The branch
is no longer documentation-only: the owner's ruling is that the documentation-only rule is a
convention for keeping rewrite diffs reviewable, not a prohibition, and it had been used twice to
decline work he wanted done. Commits are split so the one behavioural change is not buried in a
documentation diff.

- `P-2` — the schema-version refusal had no test while its sibling had one. Four added.
- `P-3` — **fixed.** `BundleWriter` now records the canonicalization version its entries carry,
  refuses a set spanning two, and keeps the build's constant for the empty set. Closing the loop
  turned the suite red immediately: `ObjectPermissionsTests` had hardcoded version 1 while the build
  produced 3, and the defect had hidden it for months by overwriting the entries' claim on the way
  in. **A self-certifying column cannot refuse anything, including data that is already wrong.**
- `P-17` — ten zero-byte files deleted. The eleventh was not a tidy-up: `.github/copilot-instructions.md`
  cited `check-instruction-claims.ps1` twice as the evidence for two claims about what does not
  exist, and the file was empty. Every claim checked out; only the proof was vapour. The script is
  written and passes, and is the only check here that tests an **absence**.
- `P-27` — S-18's *What is owed* had three claims and two were false. Corrected at source.
- `P-28` — `PunchListIdentifierTests` holds the punch list's identifiers to the tree. Found three
  orphans on its first run.
- `F-0079-6` — closed by [`0084`](decisions/0084-a-stored-fingerprints-recipe-is-pinned-to-the-schema-version.md).

**`0084` is the one to read.** A stored fingerprint's recipe is pinned to `BundleSchema.Version`, so
changing what goes into a `CoverageId` raises the schema version and old-recipe bundles are refused
at open rather than silently forming a second group. The first adjudication proposed a version
*inside* the value and was wrong for the requirement — it lets stale bundles open and group
separately, which is the failure. **Checking the whole list rather than the one entry is what
corrected it**: `AceSetHash` already puts its version inside the hash, for the opposite reason
(preventing false *equality*), and without looking the record would have contradicted the codebase
instead of distinguishing from it.

**Three punch-list adjudications came out of the first sitting and are recorded in full.** `P-2`
verified correct against the code. `P-3` decided, and since fixed. `P-7`/`F-4` demoted, which is the
one worth reading first.

**Two open findings were live in area files and absent from the punch list**, and are now carried:
`F-0079-6` and `F-0056-1`.

**Retarget and cut in the same turn as the draft.** This pass did not, for one document, and left
the repository holding two descriptions of one schema with a gate pointing at the older. The owner
caught it, not the session. Deferring deletion to a tidy-up step at the end is the same batching
failure as deferring progress updates, and it is worse here because the half-done state looks
finished.

**Done — Kernel/Schema.** One document, [`docs/schema/what-a-schema-guid-means.md`](schema/what-a-schema-guid-means.md).
`S-3-schema-guid-catalogue.md` deleted (412 lines), `SchemaGuidDocumentationTests` retargeted and the
retarget proven, `schema` added to `LayerDocuments.Subsystems`, solution items corrected in both
directions.

*The code was read whole* — 532 of 532 lines across four files, plus `CapturedSchemaGuidReader.cs`
at 267 of 267. Recorded in `_COVERAGE.md` against the archive rows, which stay unread and belong to
the later archive pass, as in Audit/Capture and Evidence.

**The boundary question was settled before drafting, and the answer is *Evidence's*.**
`CapturedSchemaGuidReader` is `internal` to `SecureAD.Evidence`; its whole body reads a bundle —
`SqliteConnection`, `BundleSchema.ColumnNameFor`, `captured_object`, an octet-string GUID whose byte
order is the trap; and the dependency runs one way, since it has `using SecureAD.Kernel.Schema` while
nothing in `Kernel/Schema` references it or could. One document per code folder puts it in its own
assembly's folder. **The cost is stated rather than hidden**: Evidence closed at five documents and
none covers it, so it is documented in *neither* layer today. That is `P-37`, and it was left as a
punch-list row rather than absorbed here — a type bound by two layer documents is the `S-18` failure,
and a pass that quietly widens its own scope to avoid an awkward remainder is choosing the larger
error. The layer document names it as the sole producer of captured entries, describes none of its
mechanics, and `TheEvidenceReaderIsNamedButNotClaimedByThisLayer` holds it out of the component
tables so a later Evidence sitting can take it without a collision.

**The retarget was proven the way this file requires, and then the proven gate found two defects in
its own document.** Pointed at `S-3` first, it failed **seven of thirteen**, each naming the table it
could not find — *has no TYPES table*, *has no KINDS table*, *has no MEMBERS table* — never an empty
scan. Repointed, it immediately caught that `SchemaGuidEntry`'s four record properties were missing
from the member table and that `IsDangerous` and `DisplayName` were named nowhere. **Both were fixed
in the document, not accommodated in the gate.** The member table is now read from a marker block
rather than by searching the whole page, which closes the weakness `F-S3-5` recorded against the old
guard and never repaired: a member could be dropped from the shape table and stay "described" by a
passing mention elsewhere.

**Two checks were deleted and the reasoning is the reusable part.**
`TheDocumentHandsEveryPreviouslyDangerousNameOnToTheNextRow` and `TheHandoverNamesARealInventoryRow`
existed *because* the danger flag had no owner — the document was the only place the nine names were
written down until K16 landed. K16 has landed, as `DangerousPermissionClassifier` with its own
document and its own gate. A check kept past the condition that justified it measures something other
than its name. What replaced them is stronger: the kind table's counts are compared against
`SchemaGuidCatalog.Embedded` rather than read as prose, so a row added to the code without the
document changing fails the build.

**Three inherited unbuilt-work claims were false, which is `P-27` holding at roughly half.** `S-3`
said the dangerous set had no owner until K16 (it ships), that nothing depended on the folder (two
callers do), and that the table had never been checked against Microsoft entry by entry (it has —
eleven of a hundred entries were wrong, and `SchemaGuidCatalogMicrosoftAnchorTests` now pins all 101
rows two-directionally). None was carried across. **Read the code for every *not built* sentence
before repeating it.**

**One number in this pass was wrong in the draft and caught by measuring rather than by review.**
101 rows over 97 distinct GUIDs was written up as *four GUIDs carry more than one row*; the
arithmetic is right and the conclusion is wrong, because `72e39547` carries three rows and not two.
It is **three** GUIDs. Inferring a count from a subtraction is the same move as summarising from
memory, one layer down.

**`D-8` is new and is deliberately not fixed.** `docs/MICROSOFT-VERIFICATION.md` records the
catalogue at 100 values; the source declares 101 and the anchor test pins 101. The likely cause is a
harvest count read as a component count, but whether that column means *values checked then* or
*values held now* changes every row in the register, so it is the harvester's to say.

**Two inbound references had to be repointed, and only one of them was reachable by a gate.**
`docs/next/README.md` links `S-3` from its status paragraph; `0016` cites `F-S3-6` in it.
`LayerDocumentGateTests` checks links *out of layer documents*, so the decision record's link would
have rotted silently. **Search for the filename across `*.cs` and `*.md` — do not rely on the gate to
find the ones it was built to find.**

**`LayerDocuments.Subsystems` now has five entries**, and adding the fifth turned on the link gate,
the solution gate and the capability gate at once, exactly as its remarks warned. The hardcoded list
of four directory names in `CapabilityCitationTests`' own summary was replaced with a reference to
`Subsystems`, so the prose cannot drift from the list again.

**Where every code folder stands.** The previous version of this line named four unstarted
subsystems and omitted `Kernel/Capture` from every list — neither done nor started, which is how a
folder gets skipped by both a reader and a successor. The whole tree, measured:

| Folder | Files | Lines | State |
|---|---:|---:|---|
| `Kernel/Security` | 23 | 3,970 | done — `docs/kernel/security-descriptors.md`, `permission-classification.md` |
| `Kernel/Schema` | 4 | 532 | done — `docs/schema/what-a-schema-guid-means.md` |
| `Kernel/Capture` | 4 | 494 | **done, and documented outside its own layer** — `docs/audit/the-attribute-catalogue.md`, because `CapturedAttributeCatalog` is kernel code on an audit subject. All four types are named, and `EveryPublicTypeInTheCaptureProjectIsNamedByACaptureDocument` holds it |
| `Audit/Capture`, `Audit/Connect` | 42 | 8,700 | done — `docs/audit/`, `docs/connect/` |
| `Evidence/Run` | 21 | 2,970 | done — `docs/evidence/`, 28 of 32 types named |
| `Kernel/Naming` | 1 | 207 | done — `docs/kernel/distinguished-names.md` |
| `Kernel/GroupPolicy` | 15 | 1,273 | not started |
| `Evidence/` root | 18 | 6,205 | not started — 30 of 44 types named nowhere |
| `Evidence/Findings` | 7 | 726 | not started — 0 of 17 types named anywhere |
| `Audit/Sysvol` | 5 | 1,122 | not started |
| `Cli` | 2 | 534 | not started |
| `Shell` | 50 | 8,518 | not started |

**`Kernel/Capture` is the rule this table exists to make visible: a code folder may be documented by
another layer's document, and that is fine — but it must be *said*, or the folder is invisible to
both the not-started list and the done list.** It is the same shape as the
`CapturedSchemaGuidReader` boundary question, one level up, and it was found the same way: by
listing the folders instead of trusting the sentence.

**Take `Kernel/GroupPolicy` next.** The kernel is closed: `Kernel/Naming` is done, and
`docs/kernel/naming.md` is a **different subject** from `docs/kernel/distinguished-names.md` — the
first is about turning stored values into words and documents `Kernel/Security`, the second is about
the distinguished name and documents `Kernel/Naming`. Both say so at the top. **They must not be
merged**, and a session that reads only the folder name will merge them.

**`Kernel/Naming` closed as follows.** `S-2-distinguished-name-manipulation.md` deleted (245 lines),
`DistinguishedNameDocumentationTests` retargeted onto `docs/kernel/distinguished-names.md` and the
retarget proven — pointed at `naming.md` first it failed **four of seven**, naming *does not name:
DnHelper*, *does not describe: ReverseDn, GetParentDn, …* and the two absent literals, never an empty
scan. Nothing was added to `LayerDocuments.Subsystems`; `kernel` was already there, so the link, the
solution and the capability gates covered the new document the moment it landed. The capability table
was **copied** from `docs/areas/who-is-who.md`, which governs the subject and keeps its own rows.

**`P-27` held again, at three of three claims this time.** `S-2` said the component was depended on
by *nothing yet* — three assemblies call it, `SecureAD.Audit`, `SecureAD.Evidence` and
`SecureAD.Shell`; that it targets plain `net8.0` — the project declares `net10.0`; and that it was 1
file of 168 lines — it is 207. None was carried across. **The consumer claim is the dangerous one**,
because it is the sentence that makes a folder look safe to change.

`P-32` and `P-33` remain open and are code rather than documentation.

---

## The cycle

One subsystem per pass. Do not start the next until the current one is committed green.

1. **Read the area file whole** — `docs/areas/`. Required by `.github/copilot-instructions.md`, and
   skipping it is how settled questions get reopened. Its *What is decided* table links the records
   that govern the area; its *What is built* table names the test proving each capability; its
   *Open findings* section holds live defects that must be carried into the punch list before the
   file is trimmed.
2. **Read every source file in the code folder, in full.** Not the summaries. See the traps below.
3. **Write the document from definitions** — the enum, the writer, the query actually sent.
4. **Carry the capability table across verbatim**, in operator voice, with its test names and lab
   dates. It is a **copy, not a move** — `AreaFileGateTests.EveryAreaFileCarriesTheThreeSections`
   requires the area file to keep its *What is built* heading permanently. Do not verify the test
   names by hand: `CapabilityCitationTests` resolves every citation in `docs/kernel`, `docs/audit`,
   `docs/connect` and `docs/evidence` against the test assembly. **Write the table under
   `## What is built`, or under `## What an operator can do` if the subsystem already uses that** —
   kernel does, the rest do not, and the gate matches both openers.
5. **Retarget the gates** that bind the old document. Retarget, do not retire.
6. **Repoint inbound references** — search for the old filename across `*.cs` and `*.md` first.
7. **Delete the old documents, and correct the solution's document items in both directions** —
   remove what was deleted *and add what was written*. Every rewritten layer document is a solution
   folder item; the Evidence pass added none, so its new document was invisible in the IDE while the
   stub it replaced was still listed. The word *prune* stood here and was read as delete-only.
   **`LayerDocumentGateTests` now enforces both halves** — every link out of a layer document
   resolves, so a deletion that left its inbound references behind goes red, and every layer document
   is listed in the solution. This was the only step of the cycle no gate covered, which is why it
   was skipped twice without anything noticing.
8. **Run the whole suite. Commit only when green.**

---

## Rules learned the hard way

**Route every fact to one destination as you read it.**

| Kind of fact | Goes to |
|---|---|
| How it works, why it is this way, do-not-change | the layer document |
| Open work | `PUNCH-LIST.md`, one table row |
| Verified already fixed | nowhere — git and the archive hold it |
| A claim the code contradicts | `_DRIFT.md` |

Writing findings into the punch list as narrative made it 724 lines — larger than the documentation
it supported. It is now 147 and must stay readable in one sitting.

**Delete by section, not by file.** Documents span subsystems. Cut the consumed part, leave the rest,
and note in the header what was taken and where it went.

**A finding is not open because a document says so.** A later document may have adjudicated it — and
that adjudication may itself be wrong. Two archived documents flatly contradict each other on GPO
link precedence; both are recorded and neither is trusted.

**Ask what a check is anchored to.** Two gates required strings from an inventory archived months
ago, and passed. A sound check pointed at a dead reference measures nothing.

**Do not hand engineering decisions to the owner.** Tooling, test structure, document shape and
naming are yours. Decide, then say what you decided and what it cost. Reserve questions for what the
product should do, what an administrator would expect, and what to prioritise.

---

## Traps

**Reasoning from comments rather than data.** XML doc comments are *never authoritative* — see the
instructions. They are argument, and they go stale: `ParsedSecurityDescriptor` still documents three
DACL states where the enum has four. Verify against the definition.

**Sampling a file and calling it read.** Large files were read at 12–20% and the drafts inherited
whatever the summaries claimed. `_COVERAGE.md` records lines read against total for this reason;
state the fraction when claiming a file is read.

**Summarising from memory at the end of a long pass.** The Audit/Capture session finished green and
then reported four document filenames that do not exist, and a deletion count 200 lines out. Both
were wrong only in the summary — the gates and the commit were correct throughout — but a reader
would have gone looking for files by those names. **At the end of a pass, read the directory and ask
`git` for the numbers rather than recalling them.** The wrongness was confident and fluent, which is
what makes it worth a line here: it is the same failure as a well-argued paragraph mistaken for a
conclusion, arriving from the other direction.

**This is also the signal to end a session.** Fabricated detail late in a pass means the useful
context is spent. Commit, update this file, and start fresh rather than pushing into the next
subsystem.

**The rule above assumes the reading is possible, and the third Evidence sitting proved it is not
always.** That session ran out of tool budget and then wrote the summary anyway, reporting one
document as undrafted when it existed and one edit as applied when it had failed loudly. The errors
pointed in **opposite directions**, which is the diagnostic: a lossy memory forgets what it did, it
does not also invent what it did not. Both directions come from one cause — **the summary was
written from the plan rather than from the transcript**, so intentions were rendered as outcomes.
Two mechanical rules follow, and neither is *be more careful*:

- **Reserve the last two tool calls of a pass for `git status --short` and `git diff --stat`.** The
  summary is written from their output or it is not written. The check that catches this failure is
  itself a tool call, so it is unavailable at exactly the moment it is needed unless it is budgeted
  for in advance.
- **No completion claim without a tool result in the same turn.** Anything unverified is named as
  unverified. *I cannot verify this* is a finished sentence.

The structural reading is worth carrying: **every claim in this repository is bound by a gate except
the session summary**, and it is the document a new session reads first. That is the same shape as
`check-instruction-claims.ps1`'s origin, arriving from the other side — there the claims were true
and the proof was vapour; here the proof was absent and the claims were false.

**A retarget is only real if the old target now fails.** When a table moves between documents,
repoint the gate and then *prove the repoint*: point it at the document the table left and confirm it
goes red. Done for the on-disk split — the misdirected gate failed ten checks naming *has no FILES
table*, *has no SEAL table*, *has no STATES table*, rather than passing against an empty scan. A gate
that parses a marker block it cannot find must throw, never return nothing; `TableRows` asserts on
the marker for that reason, and both Evidence gates carry an `AMissingTableIsAFailureRatherThanAnEmptyScan`
self-test. Two gates in this repository have already passed for months while measuring nothing.

**Read the rule, then read the code that enforces it.** Every false claim this repository has
produced sits in the *consequence* position: the rule was read correctly, the gate or the source
enforcing it was not opened, and the conclusion was written as though it followed. `P-7`/`F-4`
asserted a reader that does not exist. `0018`'s amendment was applied to three list entries and the
fourth was carried over unasked. The third Evidence sitting read *carry the capability table across,
then trim the area file* and recorded that the area files could not be trimmed — while
`AreaFileGateTests.EveryAreaFileCarriesTheThreeSections` requires them to keep that table forever, so
nothing was ever going to be trimmed. **A rule tells you what should happen; only the gate tells you
what does.** When a document states a consequence, open the thing that enforces it before believing
the sentence — including when the document is this one.

**A claim that something is *not built* is the least-verified sentence in this repository.**
gates check that every name in a document exists in the code. Nothing checks the reverse claim — that
a capability is absent — because there is no name to look up. So *What is owed* sections rot
invisibly while the paragraphs around them stay bound and true. S-18's was checked during the second
Evidence sitting: **two of its three claims were false**, and one of them was what the surface
register recorded against F6. Both described seams built after the section was written and never
re-read. **Read the code for every unbuilt-work claim before carrying it into a successor document**,
and expect roughly half of them to be stale. This is `P-27`.

**PowerShell here-strings hang the terminal.** `@' ... '@` sent as a single line never terminates:
the closing `'@` only counts at the start of a line, so the shell waits for input that is not coming
and the session has to be killed. It looks exactly like a slow command. **Write document content
with the file-editing tools and keep the terminal to commands that return** — and if a terminal call
has to be cancelled, ask whether it hung before assuming the cancellation was a judgement on the
content. One was misread that way.

**When a rule is applied to a list, check every entry before believing the list is done.** This is
`P-19`'s shape and it has now appeared four times, twice in gates that were *narrower than their own
names*. `NoDocumentClaimsADateThatHasNotHappened` matched full dates only, so a bare year-and-month
written a month early passed it. `NoDocumentLeavesADatePlaceholderUnfilled` matched an uppercase
placeholder under `StringComparison.Ordinal`, so a lowercase one passed. Both were widened; between
them they found seven wrong claims, including three lab verification dates that had never been filled
in. **Two checks can each be narrower than their names in ways that overlap, leaving a gap neither
name admits to.**

*Neither example is written out here, and that is the gate working.* Quoting the offending forms in
this file made it fail — and the first draft of this section did exactly that and was committed red.
The right repair was to describe the shapes rather than to add an exception, because an allowlist is
how a gate dies.

**A convention is not a constraint — check which one you are enforcing.** The documentation-only rule
exists to keep rewrite diffs reviewable. It was twice used to decline work the owner wanted done, on
his own branch, until he said so. That is a rule carried forward without re-asking what it was for,
which is the same failure as every stale record this pass found, committed by the session cataloguing
them.

**Traps of the same family, one layer down.** `Measure-Object -Line` undercounts, and the
Audit/Connect pass trusted it. It reported the
`_COVERAGE.md` as a coverage claim, and it named the deleted `S-14` at 175 lines when git says 225.
It appears to drop blank lines. **Use `@(Get-Content $f).Count`, or `git diff --numstat` for anything
git already knows.** Worth its own line because the previous trap says *ask `git` for the numbers
rather than recalling them* and this pass did ask a tool — the tool was wrong, and a wrong number
from a command reads as more trustworthy than a wrong number from memory.

**Capture gaps cannot be worked around later, but are not urgent.**
— the owner is the only user. A missing capture input is ordinary backlog, found naturally when a
rule needs it. Do not argue for urgency on the grounds of re-capturing a customer forest.

**The archive is outside the repository** at `C:\Users\jistrand\Downloads\SecureAD Archive\docs`.
Delete consumed sections from it as well; a second backup exists. Nothing in the repository may cite
it — a citation nobody can follow is worse than none.

**PowerShell's text cmdlets rewrite what they touch.** `Set-Content -Encoding utf8` was used to trim
`S-16` and round-tripped every em-dash through ANSI, corrupting the file it was cutting. Caught,
restored from git, redone with `[System.IO.File]::WriteAllLines` and an explicit no-BOM
`UTF8Encoding`. Same family as the `Measure-Object` trap above and worth its own line for the same
reason: a cmdlet that reads as *write these lines back* quietly did something else, and the damage
was invisible in the diff summary. **Use the .NET file APIs for any edit to a document with
non-ASCII characters in it**, which is all of them.

---

## Files that carry state between sessions

| File | Holds |
|---|---|
| [`PUNCH-LIST.md`](PUNCH-LIST.md) | open work, one line each |
| [`_COVERAGE.md`](_COVERAGE.md) | every archive file, subsystem, lines read, consumed or not |
| [`_DRIFT.md`](_DRIFT.md) | places the documentation and the code disagree |
| [`planned/effective-access.md`](planned/effective-access.md) | the specification for the two unbuilt layers |

These are the memory. A new session reads them and continues; it does not need this one's context.

---

## The single highest-priority open item

**There is not one, and the item that used to be named here has been demoted.** Read this before
picking work off the punch list, because the demotion is more useful than the item was.

`P-7` / `F-4` stood here: a lab bundle shows the `ace` table and a re-parse of the same descriptor
disagreeing by one entry — 57 against 56 — while the descriptor reports `dacl_completeness=Complete`,
with the mechanism given as a DACL walk bounded by the declared entry count rather than by the ACL's
own `AclSize`. It was never deferred on the grounds that *an operator would read an entry count that
is short, and a permission may not be listed.*

**The Evidence pass read the descriptor half of the schema back out of a bundle for the first time,
and neither half of that consequence survives.**

- The entry list an operator sees is `ObjectPermissions.Entries`, a fresh parse of `raw_bytes` with
  nothing deduplicated and nothing reordered. No permission is withheld from a screen.
- `captured_object.ace_count` is written by `BundleWriter.CountEntriesPerObject` and **read by no
  production code in the repository**. There is no reader for a short count to mislead.

**And the disagreement itself is probably designed behaviour.** The `ace` table is not a second walk
of the same DACL; it is the canonical projection, and `AceNormalizer.Normalize` deduplicates it. The
read side deliberately does not — *"a DACL carrying the same grant twice is what the directory holds
and a reader deciding it meant once is editing evidence."* `ObjectPermissions` carries the
measurement: lab bundle `ad.lab-20260819-232425`, 12,603 stored against 12,600 projected. A
one-entry disagreement on one organisational unit is one duplicated entry, and `Complete` is correct
beside it.

**One query decides it**, and it is left for a cleanup pass. Deduplication guarantees `ace` ≤
re-parse, so if the re-parse saw 57 there is no defect; if the `ace` table really saw 57 there is a
projection larger than the bytes it came from, which nothing here explains and which would be worse
than what was recorded. The punch list does not say which way round the numbers were.

**`P-7` itself stands and is ordinary backlog.** The walk really does read `AceCount` and never
`AclSize` or `AclRevision`. What it lost is its corroboration and its priority.

**The transferable part is the third instance of one shape.** An adjudication was written into the
punch list, promoted to the top of this file, and carried through three passes, and the code
contradicts it. The rule was already here — *a finding is not open because a document says so, and
that adjudication may itself be wrong* — and it applies to this file as much as to the archive.
Nothing had read the code the claim was about until the pass that owned it came round.

---

