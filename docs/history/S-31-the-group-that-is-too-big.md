# S-31 — The group that is too big

> **This records session S-31 as of 2026-08-10. Nothing here states current behaviour.**  
> It is kept for the reasoning it carries, not as documentation. See [`docs/history/README.md`](README.md).

## What this session did, and what it could not

The AD lab is not reachable from the workstation this session ran on, and the ActiveDirectory
PowerShell module is not installed there. **Task one could not be run by the session at all.** The
brief assumed otherwise. The owner ran it, and the results below are his.

- **The group is intact:** `CN=RangeLab-Oversized,OU=RangeLab,DC=ba,DC=ad,DC=lab` reports
  **2,000 members**, read back from the directory.
- **The memberships match exactly.** `Compare-BundleGroupMembership.ps1` against the bundle
  `ad.lab-20260815-031422` reports 2,000 distinct members on each side, 2,000 stored values, no
  duplicates, nothing missing and nothing extra — compared as sets of distinguished names, not as
  counts.
- **The ranged path ran, and the count is right rather than merely non-zero.**
  `attribute_blocks_fetched` is **1** on `DC=ba,DC=ad,DC=lab`. That counter is incremented once per
  *follow-up* request in `PartitionCapture.ReadEntryAsync`; the first tranche of values arrives in
  the ordinary search and costs nothing. So a 2,000-member group against a controller returning at
  most 1,500 values per response needs exactly one follow-up, for members 1,500 to 1,999 — and one
  is what was recorded. The arithmetic closes: one extra fetch accounts for precisely the values
  that could not fit, and the joined result agrees with the directory name for name.

**`F-S29-4` is closed.** Range retrieval has been exercised against a real oversized group for the
first time in this product's life, and it neither truncated, duplicated, nor lost a value. The four
ways `S-30` recorded the predecessor's range loop returning a prefix of a membership while keeping
every count consistent are all excluded by this run, because the comparison is by name and not by
count.

**What this run did not settle.** Three of the five `B20` observations owed since `S-7` remain
owed — see below. Two are answered.

## Two of the `B20` observations, answered by the same run

Neither needed instrumentation. Both follow from the fact that the retrieval *worked* against a real
controller, which is a stronger statement than anything a log line would have carried.

**`F-S7-37` — the wire spelling of a ranged attribute name. ANSWERED.** A controller answering a
too-large attribute renames it in the reply, `member;range=0-1499`. `LdapEntryReader` has to
recognise that spelling to set `AttributeCompleteness.MoreToFetch`; had it not, no follow-up request
would have been issued and the bundle would hold the first block alone. The bundle holds all 2,000
values and `attribute_blocks_fetched` is 1. So the model's spelling and a real Windows Server
controller's agree, and the claim `S-11` explicitly declined to make on the strength of a green test
is now made on the strength of a run.

**`F-S7-39` — whether a controller tolerates a base-scope search between two pages. ANSWERED, yes.**
`CaptureSearchRequestFactory.ForAttributeBlock` builds the follow-up as `SearchScope.Base`, and
`PartitionCapture.ReadEntryAsync` issues it per entry *inside* the page loop — so it goes out while
the outer paged subtree enumeration of a 6,359-object domain is still in flight, holding a paging
cookie. The enumeration completed and the membership is exact. `S-30` had this as evidence from the
predecessor's behaviour and marked it "evidence, not proof"; it is now observed directly.

## The three still owed, and why they are not urgent

**None of them can make the product state something false**, which is the only category that never
waits. Capture is fail-fast: if any of these goes wrong the run stops and writes no bundle. They are
questions about whether a run fails *cleanly*, not about whether the evidence is true.

- **`F-S7-40`, what a client sees when a paging bookmark is evicted.** The capture loop refuses a
  repeated bookmark rather than trusting it. If a real controller's eviction differs from the model's,
  the worst outcome is a failed run with an unhelpful message.
- **A controller declining a connection rung.** The most security-relevant of the three, because an
  unencrypted search can have confidential attributes stripped with no error (`F-S24-1`). But `D2`
  already answers it conservatively: an object read over an unencrypted connection reports
  `MayBeMissingConfidentialValues` whatever the controller did. Observing a real refusal would
  confirm the ladder degrades as designed, not change what the bundle says.
- **`F-S7-26`, the credential child-object measurement.** A sizing question. It says what capture
  costs, not whether it is correct.

**They should be built for, not scheduled.** All three need diagnostic output the product does not
have — there is no logging switch to turn on, and a packet capture yields ciphertext because the
connections are signed and sealed or LDAPS. That diagnostic output is wanted on its own terms, for
supporting a customer whose capture failed at hour two, and these three arrive free with it. Carrying
them as owed until then is how a list of five stops being read.

The tree is green at **846 tests**, up from 837.

## `F-S30-1` — closed

`BundleWriter.ResolveParentGuids` derived an object's parent by splitting its distinguished name on
the first comma, in SQL. A comma inside a name is escaped and separates nothing, so
`CN=Smith\, John,OU=Users,DC=corp,DC=local` was given a container that does not exist — a null
`parent_guid`, a false `unresolved_reference` row, and the object left outside the containment tree
that inherited permissions travel down. Separately, the exclusion that was meant to spare naming
context roots tested for the presence of a comma, which holds only for a root of a single label, so
the root domain of substantially every real forest was reported as a container the run failed to
capture.

**What was built.** `captured_object` gained a `parent_dn` column, written as each object is stored
by `DnHelper.GetParentDn` — the helper that was carried over from the predecessor, is correct, and
was not being called. Both statements now join on that column. Partition roots are excluded by
matching `distinguished_name` against `partition_coverage.naming_context_dn`, so the property the
original comment was reaching for — that a partition this product has never heard of behaves
correctly — actually holds.

**Storing the parent name rather than deriving it in SQL is the substance of the fix, not an
optimisation.** A distinguished name looks like a delimited list and is not one, and SQL has no way
to tell a comma that separates from one that does not. Keeping the parse in C# keeps it in the one
place that knows the difference.

**Evidence.** Three tests, all of which fail against the old behaviour and pass against the new;
the first-comma split was restored temporarily and all three were observed failing, then reverted.
The lab cannot show this defect — it holds zero objects with a comma in a name, which is why 6,359
objects across five partitions produced no sign of it.

## `F-S30-2` — the consequence, stated rather than worked around

`F-S30-1`'s fix removes the only rows anything wrote to `unresolved_reference`. The false
`DomainNotCaptured` rows were the whole of that table's traffic.

**So the table can now never have a row.** Its four-value reason vocabulary — `DomainNotCaptured`,
`AnotherForest`, `OrphanedIdentifier`, `Unreadable` — has one producer, a hardcoded SQL literal, and
no classifier. Saying so plainly is better than the alternative that was available, which was to
write a classifier in this session so the awkwardness did not have to be admitted. `F-S30-2` stays
**OPEN** and the table stays empty until something classifies.

## `F-S29-3` — `D1` and `D2` built, `D3` half built

### `D1` — built

`PartitionCoverage.IsComplete` is now `ContinuationReferencesAreComplete`, and the bundle column
`is_complete` is now `continuation_references_are_complete`. **The value did not change.** What
changed is that one word stopped carrying two meanings. Gate 4 gained the vouch shape `*AreComplete`
and, with it, a scanner self-test asserting that the shape matches the real member it was added for —
without which the widening would vouch for nothing while looking like a working pattern.

Mutation-tested both directions: removing `*AreComplete` from the shape list fails both the new
self-test and the gate's main fire.

### `D2` — built

`EvidenceObject.IsComplete` forwarded to the partition's completeness, so every domain object in a
bundle reported that we could not say whether we had looked properly while configuration and schema
objects reported that we could — the wrong answer on nearly half of a real capture.

It is now `EvidenceObject.Completeness`, an enum of `Complete` and
`MayBeMissingConfidentialValues`, decided by the rung the connection reached.

**The trap the brief named was checked and avoided.** "Was this partition read to the end" is true
of every object in every sealed bundle, because capture is fail-fast and an incomplete run never
seals. The connection rung is not: `ConnectionSecurityLevel.Signed` requires no declared allowance,
so an ordinary run lands on the unencrypted answer with nobody choosing it. Both states are asserted
by tests, and a test asserts that suppressing referrals does not reach this member — which is what
wired the two meanings together before.

Mutation-tested both directions: collapsing the switch so every rung returns `Complete` fails both
unencrypted cases.

### `D3` — derivation built, three states paused

**Built.** `CaptureRun` now derives `RunCoverage` from the partition rows capture actually recorded,
rather than asserting `plan.DeclaredDomains.Select(DomainCoverage.Read)`. Under the assertion every
declared domain reported as read *because it had been declared*, which is the statement
`RunCoverage.Of`'s guard exists to refuse — and while the assertion stood, that guard could not fire.
No new check was added; `S-29` records a third as deliberately not done and that still holds.

**Paused, at the owner's instruction, pending his re-reading of `S-30`.** `D3`'s third state,
`Unknown`, appears unreachable in any bundle the product can currently produce: `CaptureRun` refuses
a plan that does not cover every declared domain, and returns without sealing if any unit fails, so
a bundle exists only when the denominator was established. `D3` itself says `Unknown` becomes
reachable once `0040` (failover) and `0041` (parallel capture) are built, and both are out of scope
here.

Two accepted records bear on it directly, and both point the other way from `D3`:

- [`0035`](../decisions/0035-coverage-is-recorded-once-per-capture-unit.md) — "any state the
  derivation cannot produce is removed rather than kept for symmetry. A closed set with permanently
  dead members is what `0027` was written to avoid building."
- [`0027`](../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) — built on
  the same reasoning, having been written to avoid a table with four states nothing could reach.

This is a conflict between an accepted owner decision and two accepted records, and it is the
owner's to settle. **It is not a reason to withhold the derivation half**, which implements his
2026-08-10 decision and stands on its own.

#### Review addendum, 2026-08-13 — where `Unknown` came from, and why the argument for it fails here

Added after the owner asked what the reasoning for `Unknown` had been. `S-31` established that it is
unreachable; this records *why it was proposed*, because a withdrawn proposal whose reasoning is not
written down is a proposal that comes back.

**It was imported from the predecessor**, whose `RunCoverage` had exactly `Full` / `Partial` /
`Unknown`, and whose `RunCoverageResolver` returned `Unknown` when discovery was never validated or
found no domains. `S-30` quoted that code approvingly and proposed carrying the shape across.

**The import was invalid, and the predecessor's own doc comment says why:**

> A partial run is still `Sealed`: sealing means the bundle is closed and immutable, while coverage
> describes what is inside it.

The old product **deliberately sealed incomplete runs**, and it re-analysed saved captures — which
`S-15` removed. A sealed bundle there could genuinely be any of the three states. Here
[`0003`](../decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md) makes capture fail-fast, so
a bundle exists only when everything was read. `S-30` quoted that sentence without noticing that it
described the architectural precondition for the whole three-state design, and that this product
does not meet it.

**The test that would have caught it is the one `S-30`'s own brief demanded** — there must be a
reachable state in which the value is false, and a test that reaches it. `S-30` applied that test
rigorously to `D2`, which is why `D2` ended up keyed on the connection rung rather than on read
completeness. It did not apply it to `D3`. The failure was not the conclusion; it was skipping the
check on one of three proposals after passing it on another.

**The consequence reaches further than the third state, and `S-31` stopped short of saying so.** If
`Unknown` is unreachable because capture is fail-fast, then so is `Partial`, and so is
`RunCoverage.IsComplete` being false: a domain that could not be read returns before the seal, and a
domain with no recorded outcome makes `RunCoverage.Of` throw. **In any bundle a reader can open, the
run-level verdict says "complete", always.** Deriving it was still worth doing — the guard can now
catch an internal inconsistency — but it catches this product's bugs, not facts about a customer's
forest.

So the question in front of the owner is not "two states or three". It is what the run-level verdict
is *for*, given it cannot vary in a readable bundle. Keeping it as an internal consistency check is
defensible; presenting it to a reader as a statement about coverage is the defect `F-S29-3` was
raised about, one level up.

Where coverage genuinely does vary is recorded in `F-S31-5`.

#### Settled, 2026-08-13 — the run-level verdict is an enforcement, not a measurement

The owner answered the reframed question. Verified first, rather than agreed from the addendum:
`CaptureRun` is the only caller of `BundleWriter.Complete` and returns before it on any failure;
`DomainCoverage.NotRead` and `ForestPartitionCoverage.NotRead` are public and **called by nothing
outside tests**; and `RunComparability` refuses on the flag in three places, all unreachable. So the
verdict is `Full` always, and three refusals sit behind it that cannot fire.

**It is kept, and three things were done to it.**

- **Renamed** from `RunCoverage.IsComplete` to `RunCoverage.AllDeclaredUnitsAreComplete`, and the
  bundle column from `coverage_is_complete` to `every_declared_unit_recorded_as_read`. The old name
  promised a statement about a customer's forest and delivered one about our own writer. This is the
  same move as `D1`, one level up.
- **Never presented as coverage.** What a run covered is stated by the partition rows and by
  `unread_partition`, both of which vary by forest. An always-true flag rendered as a coverage
  verdict is `F-S29-3` again.
- **The invariant is now held by a test.** `UnreadOutcomeIsUnreachableTests` fails if any production
  file calls either `NotRead` factory. It does not forbid the change — controller failover (`0040`)
  and parallel capture (`0041`) both reach it — it makes the change deliberate, and says in its
  failure message what has to be decided at the same time.

**Why not delete it.** [`0027`](../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md)
rules that a run which did not read every domain may not be a baseline and may not be compared.
Today that is guaranteed upstream by refusing to seal. Deleting the check would leave the rule
stated and unenforced, and the first bundle written by a second path would carry a hole nothing
downstream could see.

**A note on the name.** The first attempt was `EveryDeclaredUnitWasRecordedAsRead`, which is more
precise and which gate 4 rejected — no vouch shape matched it. Rather than widen the gate a second
time in one session, the member took the `*AreComplete` shape `D1` had already added and justified.
The gate's own comment says widening it is how a gate dies; two widenings in one session for two
members of the same design is how that starts.

## `F-S30-3` — closed

`ControllerModel.SupportedControls` advertised paged results and nothing else, so capture never sent
the domain-scope control against the model and never suppressed referrals — while it always does
against a real controller. The model now advertises `1.2.840.113556.1.4.1339`.

**The end-to-end assertion changed value, and that is the finding confirmed.** The domain partition
now reports its continuation references as incomplete where it reported them complete before;
Configuration and Schema are unchanged. That is exactly the shape of the real 2026-08-10 bundle —
false on the domains, true on the two forest-wide partitions. The test's remarks now say so, rather
than the numbers having been quietly edited to match.

**One half of this finding could not be done here.** The brief asks that a real controller be
allowed to say what else the model is wrong about. That needs the lab. What is recorded above was
verified against the model and against the previously captured bundle, and nothing more.

## Findings

### F-S31-1 — the comparison script could not find a build it was standing next to

- **Severity:** usability of a verification tool, with one genuine correctness trap inside it
- **Confidence:** verified — observed on the lab machine, then reproduced and fixed here
- **Evidence:** three distinct faults, found one behind the other.
  - `-BinaryPath` defaulted to a path derived from `$PSScriptRoot`, correct only when the script
    runs from `tools/` in the repository. Run from a copy on a lab machine, the first symptom was a
    native DLL load failure naming a path under a repository that is not on that machine, which
    reads as a hardcoded path rather than a missing build.
  - The path given was passed to the native loader unresolved, so a perfectly ordinary
    `.\SecureAD.Cli\` failed.
  - It insisted the native library sit at `runtimes\win-x64\native`, which is where a *build* puts
    it and not where a *publish* does; and it gave no help at all to a caller who pointed at a
    project folder rather than at the build output some levels below it. That is what the owner did,
    and it is the obvious thing to do.
- **The trap, and it is the reason this is written up rather than merely fixed.** The first repair
  searched below the folder given and took the first `e_sqlite3.dll` it found. On this machine that
  is the **ARM** copy: a build output carries one per architecture. The search resolved to a real
  file, reported success, and then failed to load with *an attempt was made to load a program with
  an incorrect format* — which reads as a corrupt build rather than as the wrong copy. **A path that
  exists is not a library that runs**, and a check that confirms the first and reports the second is
  the shape of failure `docs/next/README.md` names first. The runtime identifier is now computed
  from the running process and only a matching copy, sitting beside `Microsoft.Data.Sqlite.dll`, is
  accepted.
- **How it was acted on:** all three fixed, and the resolution proved by running the script's own
  block against both a project folder and a build output and requiring SQLite to open in each — not
  merely requiring a path to exist. Both resolve to the same folder and report SQLite 3.41.2.
  **Closed.**

### F-S31-4 — the check that made the comparison mean anything was left to the operator

- **Severity:** a verification tool that can report success while having verified nothing
- **Confidence:** verified — observed on the owner's run of 2026-08-12
- **Evidence:** on a match, the script printed
  `SELECT naming_context_dn, attribute_blocks_fetched FROM partition_coverage` as a suggestion, said
  the value must exceed zero, and exited **0**. A group small enough to fit in one response matches
  trivially, so without that query the green result is not evidence about range retrieval at all —
  and the operator's actual run produced a passing verdict with the query unrun.
- **What happens to a user:** a run reports `Membership matches exactly` in green and exits
  successfully, and a reader concludes range retrieval is verified when nothing has shown that it
  ran. That is the category `docs/next/README.md` names first: a check that passes while measuring
  nothing.
- **How it was acted on:** the script already had the database open and the object in hand, so it now
  joins `captured_object` to `partition_coverage` on the group's own coverage row, prints the
  partition and the block count, and **exits 1** when the count is zero or the coverage row is
  absent — saying that the match proves nothing rather than reporting success. Exercised both
  directions against a purpose-built database: two blocks passes, zero blocks refuses with exit 1
  while the memberships still match exactly. **Closed.**

### F-S31-3 — the lab tooling is not in version control

- **Severity:** the verification tools can differ between machines with nothing to say so
- **Confidence:** verified — `git status` reports both as untracked
- **Evidence:** `tools\Compare-BundleGroupMembership.ps1` and `tools\New-LabOversizedGroup.ps1` have
  never been committed.
- **What happens to a user:** the copy on the lab workstation and the copy in the repository drift,
  and a verification tool that quietly differs between two machines is the same category of problem
  as a check that passes while measuring nothing — the fixes above would not reach the lab, and
  nothing would report that.
- **How it will be acted on:** commit both.
- **Status:** **OPEN**.

### F-S31-2 — `unresolved_reference` can no longer have a row

- **Severity:** correctness — a table and a four-value vocabulary that nothing can populate
- **Confidence:** verified — `F-S30-1` removed the only producer
- **Evidence:** see `F-S30-2` above. The single producer was the false-parent path, now gone.
- **What happens to a user:** genuine unresolved references — a foreign security principal, a trust
  to another forest, an orphaned SID — are recorded nowhere at all, where before they were recorded
  wrongly. Whether that is worse is a real question and not one this session settled.
- **How it will be acted on:** not here. It wants the classifier `F-S30-2` describes.
- **Status:** **OPEN**.

### F-S31-5 — the partitions a run declines to read are printed and then forgotten

- **Severity:** correctness — the evidence does not state a part of the directory the run did not
  read, which [`0017`](../decisions/0017-capture-reads-the-whole-forest.md) requires it to state
- **Confidence:** verified by reading every reference to the value
- **Raised:** 2026-08-13, during the review of `D3` recorded above
- **Evidence:** `ForestDiscovery` produces `PartitionsNotRead` — application partitions the forest's
  own cross-references declare and that capture does not read. The 2026-08-10 run had four. The
  value reaches `CapturePlan.NotRead`, and outside the plan it is referenced in exactly one place:
  `Program.cs:156`, which prints it to the console. **It is never written to the bundle.** There is
  no table for it, and `RunCoverage.UnreadForestPartitions` is not it — that covers the
  configuration and schema partitions, which every forest has exactly one of.
- **What happens to a user:** the console says four partitions were not read; the evidence says
  nothing. Anyone reading the bundle afterwards — which is the only durable artefact, and the thing
  a comparison runs against — cannot tell that those partitions exist. Their absence is
  indistinguishable from a forest that does not have them, which is the inference
  [`0002`](../decisions/0002-absent-view-means-degraded-run.md) forbids being available.
- **Why it is this way:** the value was produced for the operator's benefit at the moment of the run
  and nobody asked whether the evidence needed it. `F-S28-2` was the same value being asserted about
  rather than measured, so this has been looked at twice without the question being asked.
- **Why it matters to `D3`:** this is the statement of incompleteness that genuinely varies by
  forest and by run. The instinct behind `Unknown` — that the evidence needs somewhere to say it did
  not see everything — was sound; `S-30` put it in the run-level verdict, where it cannot vary,
  instead of here, where it does.
- **How it will be acted on:** not settled. It needs a decision about whether unread partitions are
  coverage rows, a separate table, or a field on the bundle, and `0035` governs that choice.
- **Status:** **CLOSED, 2026-08-13.** Built as a table of its own, `unread_partition`, one row per
  partition the forest declares and the run declines to read. Written by `CaptureRun` before the
  first read, since it is a fact about the plan rather than about anything a pass discovered.

  **Why a table of its own.** `0035` makes `partition_coverage` the positive record of what a
  capture unit read. Nothing here was read, so its controller, pages, objects and connection rung
  have no value, and rows carrying none of them would make every existing count of partitions read
  wrong without raising an error. A field on the run record was the cheaper option and was rejected
  for the reason `0035` exists: it would be a second, independently asserted account of what the run
  covered, sitting beside the derived one.

  **No reason column**, because every row has the same cause — the DNS scope decision of
  2026-08-11 — and a vocabulary with one hardcoded literal filling it is `F-S30-2` rebuilt in a new
  table. A second cause is when the column earns its place.

  **The DNS scope question was checked against Microsoft's documentation before building**, at the
  owner's request, and the existing decision survives it. Application directory partitions use the
  same access control model as any other partition and the DNS zones in them are open by default —
  "any authenticated Active Directory user can create the A or PTR RRs in any zone" — so the
  partitions are not empty of security meaning. But they **cannot contain security principals**, so
  nothing in them can be a hop or a holder, which is the same test `0034` applies to the shipped
  noise list. The permissions on the zones are therefore the only thing being given up, no rule in
  the catalogue evaluates them, and the owner's standing position is that capturing evidence no rule
  can assess is not worth the cost. `CapturedAttributeCatalog.UnreadObjectClasses` already states
  the precise sentence a report must carry: DNS zone and record permissions are not assessed, and
  DNS administrative group membership is.

  **The near-miss, recorded because it is the point of the exercise.** The first version of this was
  tested only against `BundleWriter.RecordUnreadPartition`. Emptying the loop in `CaptureRun` — so
  that nothing ever called it — left the entire suite green. A written value that nothing writes is
  the failure this repository keeps producing, and it was reintroduced within an hour of a session
  spent removing two instances of it. An end-to-end assertion was added, and the same mutation now
  fails.

### F-S31-6 — the DNS scope decision is a code comment, not a decision record

- **Severity:** authority — a customer-facing statement rests on something this repository defines
  as discussion
- **Confidence:** verified — `git grep` finds no record in `docs/decisions/` covering DNS or
  application partitions; the only statement is the remarks on
  `CapturedAttributeCatalog.UnreadObjectClasses`
- **Raised:** 2026-08-13
- **Evidence:** the decision is dated 2026-08-11 in that comment, is enforced in two independent
  places — the class exclusion and the partition skip — and is now written into the evidence a
  customer receives. [`README.md`](../next/README.md) is explicit that only a record in `docs/decisions/`
  with `Status: Accepted`, or a finding carrying a `Decision:` line, states the product's position.
  A doc comment is neither.
- **What happens to a user:** the owner intends to state in the help file that DNS zone permissions
  are not assessed and must be checked by hand. That is the right thing to say, and it will be the
  first written statement of a choice the product has been making silently. If it is ever
  questioned, the answer lives in a comment on a static property.
- **How it will be acted on:** write the record. It is short, the reasoning already exists in two
  places, and `0034` is the model — it covers the same category of choice.
- **Status:** **CLOSED, 2026-08-13.** Written as
  [`0042`](../decisions/0042-dns-zones-and-records-are-out-of-scope.md). Nothing about the decision
  changed; it acquired the authority it was already being treated as having. Both enforcement points
  — the class exclusion and the partition skip — now cite it rather than restating it, and the record
  asks that they be changed together. The Microsoft evidence is in the record's Context, including
  the point that settles it: an application directory partition cannot contain a security principal,
  so nothing in one can be a hop or a holder, which is the same admissibility test `0034` applies.

## What the next session does

1. **`F-S30-3`'s other half** — what else a real controller says the model is wrong about.
2. **Diagnostic output for the product**, wanted on its own terms for supporting a failed capture.
   The three remaining `B20` observations arrive with it and should not be scheduled separately.
4. **`F-S30-3`'s other half** — what else a real controller says the model is wrong about.
5. **Commit the lab tooling** (`F-S31-3`).

## Housekeeping

Still uncommitted from `S-29` and `S-30`: `next/ad.lab-20260815-010309/`,
`next/tools/Read-Bundle.ps1`, `next/tools/row-a7.txt`, `next/tools/row-a9.txt`,
`tmp-bundle-query/`. Unchanged by this session and still needing to be moved, deleted or ignored.

The lab OU at `OU=RangeLab,DC=ba,DC=ad,DC=lab` must stay until task one has produced its answer.
