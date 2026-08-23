# The rebuild

The new product's library, and the record of building it.

Per `0009` the new
implementation is built in this repository, beside the existing one. Per
[`0013`](../decisions/0013-the-bundle-is-no-longer-a-two-way-contract.md) the `audit.db` bundle is
no longer a contract between them: the rebuild writes whatever schema it needs and the old
application is not expected to open it, so there is no working product end to end until connect,
capture and storage are rebuilt. Per `0012`
it lives at [`next/`](../../next/README.md) and builds from `next/SecureAD.Next.sln`, so the old
tree's architecture tests do not govern it. This folder is where its documentation lives while that
is true.

**Open the solution you intend to change.** `next/SecureAD.Next.sln` for the rebuild,
`SecureAD.sln` for the old product. They do not reference each other, and a session started against
the wrong one will read the wrong tree.

**Start at [`ARCHITECTURE.md`](ARCHITECTURE.md)** if the question is *how is this put together* — the
stages a run passes through, the projects they live in, and which project may use which. It is
written as the product is built rather than afterwards, so a stage that says *not built* says so.
This file is about how the work is done; that one is about what is being made.

## Where to look, and what each place is allowed to say

Reorganised 2026-08-14, because the same fact was written in too many places to keep them agreeing.
See §`One fact, one home` below for what was measured and why.

| Question | Where | What it may contain |
|---|---|---|
| What is this part of the product for, and what is built? | [`docs/areas/`](../areas/README.md) | **Start here.** One short file per area: what is decided, what is built and the test proving it, and what nobody has discussed yet |
| What has this product decided? | [`docs/DECISIONS.md`](../DECISIONS.md) | **Generated.** Never edit it; run `next/tools/Build-DecisionIndex.ps1` |
| Why was it decided that way? | [`docs/decisions/`](../decisions/README.md) | The reasoning. **The only place a decision is stated** |
| What does this component do? | `docs/next/S-*.md`, named for the thing | A description of something that exists, bound to the code by a test |
| What did the old app have? | `WHAT-THE-OLD-APP-HAD.md` | An inventory of the predecessor, read as research. **Nothing in it is owed** — it never says what is left |
| What did somebody find on a Tuesday? | `docs/history/` | Dated narrative. **Never read to find out what is true** |

The split between the third row and the last is the one the tests already implied: **a document
named for a thing is documentation; a document named for a session or an activity is history.**
Thirteen `S-` documents describe a component and are bound by a test, and they stayed. Thirteen more
described a session, were bound by nothing, and moved — and every documentation contradiction found
on 2026-08-14 came from that second group.

## Two libraries, and nothing moves between them

**`docs/` is the old product's library.** It describes code that still runs. Nothing in it is edited
to describe the new code, and most of it is deleted when the old code is.

**`docs/next/` is the new product's library.** Everything in it is written fresh.

Old documents are **source material**, not inheritance. A rule specification, a data model, an
architecture note — each is read the way you would read a specification someone handed you: it tells
you what the product does and why, and it does not become the new documentation by being moved.

This costs time. It is the point. The old library is thirty-three thousand lines written across a
period in which the product's identity changed twice, and the map found six kinds of claim in it
that were true when written and are not true now. Copying it forward would carry those in without
anyone deciding to.

When the old code is deleted, this folder is promoted to `docs/` in one move, and the old files go
with the code they describe.

### The one exception

**Decision records stay in [`docs/decisions/`](../decisions/README.md).** They are dated records of
choices made on a particular day with the reasoning as it stood. A record wholly replaced is
superseded; a record partly overtaken is **corrected in place**, keeping its `## Context` section as
written so the reasoning that produced the error survives. Git is the history. See
[`0032`](../decisions/0032-a-decision-record-is-corrected-in-place.md), which replaced an
append-only rule that put corrections at the top of a file where `git grep` could not see them.

They are reviewed rather than inherited. Before the first port session, each existing record is read
and either confirmed as still binding on the new product or superseded by a new one.
[`0008`](../decisions/0008-live-verification-is-removed.md) already did that to three.

## When a document counts as documentation

> **A document is not the new product's documentation until a test binds it to the new code.**
>
> **And a test binds a document to the code only if it derives what it expects from the code.**

The first line was the rule from the start. The second was added on 2026-08-14, after the first was
applied to documents describing other documents until the suite policing prose was larger than the
suite covering the product.

**The test that decides it: what change to the product would make this fail?**

If the answer names a change — adding a table, renaming a member, removing an enum value — the check
is **generative** and belongs in the test suite. `HistoricalRecordDocumentationTests` reads the
`CREATE TABLE` statements out of `BundleSchema.cs` and holds
[`what-a-bundle-holds.md`](../evidence/what-a-bundle-holds.md) to them, so a twelfth table fails
the build until it is described. `GoverningDocumentTests` globs `next/src` and holds
`READING-ORDER.md` to what is there. `DecisionIndexTests` holds `docs/DECISIONS.md` to the records it
is generated from.

If the answer is *nothing — only editing the document it is about*, the check is **pinning**, and it
does not belong here. A pinning check hardcodes the instance somebody already found by reading. It
cannot find the next one, because the next one is in a different file with different wording.

That is not hypothetical. `DecisionRecordRepairDocumentationTests` opened by recording that
`PointInTimeReviewTests` *could not catch the class of defect it found, and that a person reading
thirty documents found it instead* — and the response was another test naming the five files the
person had found. Twelve such files were deleted on 2026-08-14 along with six assertions inside
files that were otherwise sound. The suite went from 960 tests to 793.

**Two habits produced them, and both are now out of bounds.**

- **Do not test the shape of prose.** Heading formats, finding identifiers, status lines, whether a
  section exists. `EveryFindingCarriesAnIdentifier` appeared in three files and asserted that
  markdown headings contained a string. One of them conceded in its own remarks that the check could
  be answered by renaming prose, which is the confession that it was testing the document.
- **Do not pin a correction.** A test asserting a document still contains the sentence
  ``Corrected 2026-08-13 in `S-26` `` fails when you reword your own note, and one of the deleted
  checks asserted that an inventory row *still held a stale value* so that a note about that staleness
  stayed true. Keeping a document wrong so a correction remains accurate is not a test.

**What replaces them is review.** That a finding carries an identifier, that a decision record still
points at the one that corrected it — these are real obligations and they are checked by a person
reading, which is what was catching them anyway. The tests added nothing except the appearance of
coverage and a build that went red when prose changed.

### One fact, one home

> **If a fact can be derived from a source, derive it. Never write it down beside the source.**

Measured on 2026-08-14: every decision record was referenced in an average of **sixteen** other
files, and sixty sentences of sixty characters or more appeared verbatim in two or more files. At
that fan-out a decision that changes needs sixteen correct edits or it contradicts itself, and it
already had — `S-15` said the capture entry point takes a destination, `0025` decided two days later
that it does not, and the inventory row and a class comment had both copied the first.

So:

- **A decision is stated once**, in `docs/decisions/`. Everything else cites the number and does not
  paraphrase the reasoning.
- **The index over the records is generated**, at [`docs/DECISIONS.md`](../DECISIONS.md), by
  `next/tools/Build-DecisionIndex.ps1`. Never edit it; regenerate it.
- **Session narratives are history**, in `docs/history/`, and are never read
  to find out what is true.
- **An inventory row carries status and citations**, not argument. If a row makes you want to explain
  something, the explanation belongs in a decision record.

### What binding does not do

A test can assert that a document names every rule that exists and no rule that does not. It cannot
assert that the explanation of why a rule matters is any good. Tests catch drift and omission; a
human catches bad writing. Both are required.

### The scanner still tests itself

A document scanner that matches nothing passes forever, and this repository has shipped that failure
three times — `F-S7-41`, `F-S7-43`. So a generative check keeps its self-test: one case proving it
finds the document and the component, and one proving it reports a name that is absent. Those stay.
They are the cost of the check being trustworthy, not paperwork about paperwork.

## Tests

Tests are code, so [`0011`](../decisions/0011-rebuild-documentation-is-written-fresh-and-bound-by-tests.md)
does not govern them. The spirit is the same — review rather than inherit — with one deliberate
exception, and it is the important one.

**Oracles are copied exactly, and never rewritten.**

An oracle is a frozen record of what the old system produced: the classifier fixtures under
`tests/…/EscalationPaths/Fixtures/`, and the hash constants in `GoldenFileDeterminismTests`, which
its own remarks describe as *"computed once and hardcoded"*. These come across byte for byte.

A golden value edited to match what the new code produces proves nothing. It deletes the evidence
and keeps the ceremony. So: **a golden value that needs editing is a finding, not a fix.** Stop,
record what changed and why, and decide deliberately whether the new behaviour is right — that is a
conversation, not an edit.

`BenchmarkSuite1` is the same kind of asset for performance rather than correctness, which is why it
is deferred rather than deleted.

**The suite is weighted towards the product, and that is measured rather than assumed.**

On 2026-08-14 it was not. `Documentation` was the largest area in the test project — 5,905 lines and
169 tests — against 3,024 lines for `Kernel`, which holds the security-descriptor parsing, and 1,534
for `Capture`, which is the code that talks to a domain controller. Counting `Architecture` and
`Ledger` with it, more than half the suite was checking the repository's own paperwork.

So, before adding a documentation check, count. **If `Documentation` is approaching the size of
`Kernel`, the answer is not another check.** The reason this matters is not tidiness: every one of
those tests makes a document harder to change than the code it describes, and in a repository with
fourteen lines of prose per line of working code that ratchet points the wrong way.

**Cases are reviewed and carried.** The scenarios a test covers — deny sorts before allow, a null
DACL is not an empty DACL, a non-canonical ordering must still normalise — are knowledge about
Active Directory, and they survive any rewrite. Read them, check them, carry them. Do not copy them
on faith.

**The harness is rewritten.** Arrange and act, helpers, naming. It is written against the old API
and there is nothing to preserve.

**Assertions are re-derived, not inherited.** A ported test encodes old behaviour as a requirement,
including the behaviour that was wrong. `VerifyLiveAclAsync` swallows a `SqliteException` during its
stored comparison, so a comparison that *failed* reports "Live ACL matches snapshot." A test
asserting that message passes. Carried over unreviewed it stops being a bug and becomes a
specification, and the next person to fix it sees a red test and assumes they broke something.

Where a source of truth exists — `docs/rules/` — the
assertion comes from there rather than from whatever the old test happened to check.

## Gates

The map found six things recurring across three or more branches independently — that is, found
separately by sessions that could not see each other's work. Each is a way this codebase went wrong
more than once, so each becomes a build failure in the rebuild tree rather than a guideline.

| # | What went wrong before | How it is prevented | State |
|---|---|---|---|
| 1 | A correct mechanism built, and no boundary obliging its use | `Result<T>` and `AuditError` are types, so the compiler enforces them. Plus: no service constructor parameter may default to `null` — that is how progress, cancellation and the performance log all became optional and unused | **done** — `NullDefaultGateTests`. Enforced as the wider rule, no production parameter at all, because a text scan cannot tell a constructor from a method |
| 2 | The same question answered three to six times, differently | A concept registry: named concepts, one owning type each, and a test that fails when a second type declares a matching member | **done** — [`CONCEPT-REGISTRY.md`](CONCEPT-REGISTRY.md), enforced by `ConceptRegistryTests`. `SchemaGuidSingleSourceGateTests` is a second, narrower instance of the same gate, forbidding a GUID literal outside the catalogue |
| 3 | No artefact states the age or provenance of its evidence | Every artefact writer emits `run_id` and `SealedUtc` | **phase 2** |
| 4 | "Found nothing" and "could not compute" rendered identically | No public method returns a bare count; it returns a vouched type or a `Result<T>` | **done** — `S-6-vouched-returns.md`, enforced by `UnvouchedResultGateTests`. A count is recognised by its name, because an `int` carries no units and a rule firing on every `int` would forbid an access mask; a collection is bare when its declaring type carries no `Errors` or `Verdict` beside it. One exemption, `SchemaGuidCatalog`, with a decay test that fails when the catalogue gains a way to fail |
| 5a | Dead surface accumulating unnoticed | Every public type is listed in [`SURFACE-REGISTER.md`](SURFACE-REGISTER.md), claimed by exactly one area in [`docs/areas/`](../areas/README.md). A type claimed by no area, or by an area that does not exist, fails the build | **done** — `SurfaceRegisterTests`. Keyed to areas since 2026-08-16; it previously named the inventory row expected to consume the type and failed when an entry outlived that row, which stopped being meaningful when the inventory stopped carrying a status |
| 5b | The same, but proved rather than promised | Every public type is reachable from a running entry point. Uses the compiler's own view of the code, so a mention in a comment does not count as use | **blocked** — nothing traces reachability. The entry point it once waited for exists: the shell ships and a run can be started from it. What is missing is the trace itself, from that root through the compilation. Recorded as `F-S7-42` |
| 6 | Names describing an intention rather than the code | Not mechanically testable. Review only | — |

A seventh guard is not on that list because it is not a map finding: every `.cs` file under `next/`
must be compiled by a project in `SecureAD.Next.sln`. It exists because a stale project folder
survived a rename during setup and the file-scanning guards, which read the file system rather than
the compilation, scanned it.

Gate 5 is the one that gets more expensive every week it is deferred. It cannot be retrofitted onto
a large codebase, which is exactly why the old one carries six unreachable grids and twenty-eight
commands bound to nothing.

**It was originally written as one gate, and the wording did not work.** Stated as *"every public
type has a production consumer"*, it passed on 2026-08-10 against all fourteen public types in the
rebuild — while nothing in the tree was used by anything that runs. The types reference each other,
which satisfies the wording; and `SecurityDescriptorParser`, the entry point of the component built
that week, had exactly one production reference in the whole tree, inside an XML doc comment.

That is worse than an absent gate. An absent gate is visibly missing. One that always says yes
looks like protection.

The failure it exists to catch is not "nothing mentions this" — the old product's six unreachable
grids mention plenty, and mention each other. It is **"nothing that runs can get to this"**. That
is reachability from a root. When the gate was split there was no root to measure from; the shell
has since shipped and there is one. What is still missing is the trace itself — nothing walks the
compilation from that root — so 5a enforces the bookkeeping and 5b stays blocked on the measurement
rather than on the entry point.

Written so far, in [`next/tests/SecureAD.Next.Tests/Architecture/`](../../next/tests/SecureAD.Next.Tests/Architecture):
[`ProductInvariantTests`](../../next/tests/SecureAD.Next.Tests/Architecture) asserts invariants I-1 and I-3 explicitly rather than inheriting them,
`GreenfieldGateTests` confines directory reads to the capture project per
[`0008`](../decisions/0008-live-verification-is-removed.md) and holds the orphan guard, and
`NullDefaultGateTests` holds gate 1's second half, and `ConceptRegistryTests` holds gate 2 against
[`CONCEPT-REGISTRY.md`](CONCEPT-REGISTRY.md), and `UnvouchedResultGateTests` holds gate 4. Each
carries the scanner self-tests below, and
all were mutation-tested in both directions.

Gate 1's guard caught two offenders on its first run, both in `AuditError` — the type that is gate
1's *other* half. Neither was a collaborator quietly made optional, which is the failure the gate
names; they were an optional string. The defaults came out anyway, because a gate its own author
exempts is not a gate.

**Every gate carries two companions**, following the pattern the old tree already uses: a scanner
self-test, so a gate cannot pass by looking at nothing, and — where it needs exemptions — an
allowlist-decay test, so an exemption that is no longer needed fails the build rather than becoming
permanent.

## How to continue this work

**One inventory row, or one small group of them, per session.** Never "work on the kernel". The map
already sized every component, which is what makes a scope like *K15* honest and *the kernel* not.

**Tests first on a port.** Take the existing tests across, run them red against the new project, then
move production code. See §Tests for what is copied exactly, what is carried, and what is rewritten.

**Decisions are the owner's, and a session waits for them.** Tooling, code layout, test structure and
technique are the session's to settle. What the product does, what it stores, what it tells a
customer and what it refuses are not — those are presented with the options and their costs, and the
session waits for an answer before writing code. **A brief saying "decide X" is not delegation of a
product decision.** This is recorded here because it was got wrong: a session was told to decide six
open points, decided them, built to them, and four did not survive review.

**Where a decision rests on what the old implementation did, read the old implementation.**
`docs/map/` is a summary written by a different session at a different time. It
names the file to open; it is not the evidence. Three claims taken from it on 2026-08-12 were
contradicted by the code — see `F-S15-9` in `S-15` — and two of them
had already been built.

**Record a decision when it is made, not at the end.** A session that batches its documentation is
one interruption away from losing all of it. If recording is deferred, say plainly that nothing is
written down yet, so it is the owner's risk to take rather than a silent one.

> ### The code in `SecureAD.Evidence` does not match the decisions
>
> As of 2026-08-13, [`next/src/SecureAD.Evidence/`](../../next/src/SecureAD.Evidence) still holds
> writers built on 2026-08-12 and **superseded by review the following day**. It has no re-analysis
> path, which [`0021`](../decisions/0021-re-analysis-produces-a-new-bundle.md) restored; and its
> seal is framed as a tamper control, which
> [`0020`](../decisions/0020-the-seal-detects-corruption-not-tampering.md) rejected.
>
> **The schema is rebuilt and is no longer among the superseded code.** How an object's attributes
> are stored was corrected at **S-24** on 2026-08-13 — name/value rows became typed columns per
> [`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md) — and the security-descriptor
> half was rebuilt at **S-25** on 2026-08-13: descriptors are deduplicated on a cryptographic hash
> of their bytes with entry sets held once each, a measured 4.81 GB down to 1.24 GB per 100,000
> objects; the raw bytes are stored; and an object whose descriptor could not be read at all now has
> a row saying so. `BundleSchema.cs` no longer holds pre-review work. `what-a-bundle-holds.md`
> describes what the code creates, in both directions.
>
> **Read the decision records, not that code.** The inventory rows carry `rebuilding after review` for
> the same reason. It has not been deleted because it still holds work that survives — the bundle
> layout, the partial-file mechanism, and the guards — and deciding what to keep is part of the next
> storage session rather than a tidy-up.

## How a session is started

**The prompt is a file, written before the session runs**, in
`sessions/` and named for the slice it will produce. Start the session by
pointing at that file.

Until 2026-08-12 the prompt was assembled by hand into a chat window from a template that lived
here. Three things were wrong with that. The prompt actually used was never recorded, so *what was
this session told to do* had no answer and a slice document could not be read against its own
brief. Each expansion was a fresh chance to drop a rule, and an expansion that quietly omits
`§Tests` looks exactly like one that does not. And nothing checked that a prompt pointed at
documents that still exist, so a session sent to a renamed file finds nothing and carries on.

Until 2026-08-14 `SessionPromptTests` held every prompt to four headings — `## Scope`,
`## Read first`, `## Rules`, `## Finish by` — and checked that every document it named existed. It
was deleted with the other checks that compared one document to another: it could not be broken by
any change to the product, and what it could not check was the part that mattered — whether the
scope is the right scope, or whether the rules named are the ones that matter. **A prompt is now
read before the work rather than validated by a build.** That is why it is written down in advance
rather than reconstructed afterwards.

**Prompts name sections rather than repeating them.** A prompt carrying copies of the rules drifts
from them and nothing can reconcile the two; that has already happened once in this repository.
Naming them keeps one copy, which is the reason, and it holds whether or not a test is watching.

`sessions/S-19-point-in-time-review.md` is the worked
example, and the next session to run.
## Status

Phase 0. The scaffold exists, the cross-cutting contracts are written, and gates 1, 2, 4 and 5a are
fully enforced — every gate that can be. Of the rest, gate 3 is phase 2, gate 5b needs something
that runs to trace from, and gate 6 is not mechanically testable and is caught by review or not at
all. Five components are done, all of them the kernel: K13, K14, K15, K16 and K17 —
the security descriptor parser and ACE canonicaliser, the schema GUID catalogue that replaces the
two tables K13 and K14 were, the dangerous-permission classifier, and the distinguished-name
helpers. They are documented at [security descriptors](../kernel/security-descriptors.md),
[`S-2`](S-2-distinguished-name-manipulation.md), [`S-3`](S-3-schema-guid-catalogue.md) and
[permission classification](../kernel/permission-classification.md), each bound by a test. The gates themselves are
documented at `S-5` and `S-6`. Gate 5b
stays blocked, though no longer for the reason first recorded: the shell ships and a run can be
started from it, so the root exists. Nothing traces reachability from it.

The first twelve capture rows — B1 through B12 — now carry dispositions, decided together at
`S-7` and bound to the inventory by a test. Eleven are Rebuild and one,
the concurrent shard fan-out, is deferred against a measured baseline. Five of them are built.
B2 — the catalogue of attributes capture asks a domain controller for — is documented at
[`S-8`](../audit/the-attribute-catalogue.md) and bound by a test that fails when an attribute cannot
name something that reads it. It was the first code in the rebuild outside the kernel. B4 and B7
followed: the **capture unit**, documented at [`S-9`](../audit/the-search-capture-issues.md), which is one naming
context on one domain controller and the reason a paged search based at a domain root cannot be
allowed to follow anything; and the **politeness rules**, documented at
[`S-10`](../audit/limits-and-failures.md), which name the limits a domain controller sets rather than guessing
at them and replace the deleted rate limiter with a build failure. Both documents are bound by
tests, and both say plainly which half of their obligation cannot be bound yet.

B8 followed on 2026-08-11: **the reader**, documented at
[`S-11`](../audit/how-a-controller-is-read.md), which turns what a controller sends back into
typed values and carries the range-retrieval rule. A domain controller will not return more than a
fixed number of values for one attribute of one object, and an administrator cannot lift that
limit out of the way, so a reader that does not ask for the rest reports a ten-thousand-member
group as a group of fifteen hundred and reports it calmly. There is no cap on how many blocks a
retrieval takes, because a cap that returns what it has is that same defect wearing a limit; what
bounds it instead is that every block must advance, and a block that does not is a stated failure.
The document is bound by a test, and it says which half of its obligation a repository without a
forest cannot reach.

B6 followed on 2026-08-12: **the capture passes**, documented at
[`S-12`](../audit/how-a-controller-is-read.md). This is the loop that issues a search, takes a page, asks for
the next and knows when a partition is finished, plus the rule for which partitions a run reads at
all. Its one job is to never report a partition as read whole when it was not, and the way it does
that is worth reading: the paging defect cannot be detected from any answer, because the controller
sends a good bookmark and the client library throws it away, so the loop refuses to make the claim
unless the connection has told it that referral chasing was off. A completed pass is a
`PartitionCoverage`, and the existence of one is the claim — everything else ends the run. The two
old passes over the same objects are merged into one, and the security-descriptor flags control that
made a second pass look necessary is simply on the first, which also closed a real gap: the control
had been lost between the row that built the request and the row that issues it, so a capture would
have needed a privilege on every domain controller.

**Nothing still runs, and B6 did not change that.** The loop has no caller: choosing a controller and
opening a connection is branch A, and writing what it reads to a bundle is branch C, and neither is
decided. So gate 5b stays blocked, and what is missing is not a component but an entry point. Its
trigger, and the sixteen surface-register forecasts that named B6 as the first *running* consumer,
move to **B20** — capture run bookkeeping — which is where a run driver lands. That is the second
time a forecast has moved for this exact reason, and it is recorded as `F-S7-42` rather than fixed
quietly.

Branch A followed on 2026-08-12, and it is where a customer's credentials and a customer's evidence
cross a network. **All ten rows, A1 to A10, now carry dispositions**, decided together at
`S-13` and bound to the inventory by a test: six Rebuild,
one Delete, two Defer, and A2 built. The deletion is the routing table with failover — a session-wide
answer to *"which controller do I use for domain X right now"* — which is wrong here because a unit
names its controller before the run starts, the failure policy already decided what happens when one
stops answering, and half a partition from one controller and half from another is two views of a
replicating directory stitched together with nothing recording the seam.

**How this product connects to a domain controller was settled by the owner**, and it is recorded at
[`0018`](../decisions/0018-connection-security-is-an-ordered-ladder.md). Connection security is an
ordered ladder of named rungs — LDAPS, then signed and sealed, then signed, then unprotected — walked
from the top until one answers. It is a list rather than a chain of branches, so a fourth rung is an
entry rather than an edit everywhere. The bottom rung is reached **only where the auditor declared,
before the run started, that this run may use one**: a declared allowance and never a fallback,
stated per run and never remembered, because a persisted setting is one somebody turned on once and
nobody has thought about since. There is no prompt at the moment of failure, because an audit tool
gets scheduled and a run that blocks at 03:00 has done nothing by morning. Simple binds are not on
the ladder at all — Microsoft's own account of one on port 389 is that there is *"no security for
these sessions… because credentials are transmitted in clear text."*

A2 — **the connection** — is built and documented at
[`the connection ladder`](../connect/the-connection-ladder.md) and
[`how a connection is opened`](../connect/how-a-connection-is-opened.md), with the
ladder as a table bound to the rungs the code names. It implements the seam B6 wrote and left open,
and the seam held unchanged, which is recorded as a table rather than asserted. The rung each
controller answered on is kept by name rather than as a flag, because a flag has nowhere to put a
third state and this ladder has four — and because walking it produces, at no extra cost, a
per-controller inventory of what a customer's domain controllers will accept.

**Nothing still runs, and branch A did not change that either.** A2 opens a connection when something
calls it and nothing does, so gate 5b stays blocked and its trigger stays on B20 rather than moving
for a third time. What is still missing is named rather than implied: a run driver at B20, somewhere
to write what is read in branch C, and an entry point at A9 or J1 — A9 being deferred behind B20 for
the same reason. That is `F-S13-3`. Two obligations this branch created but cannot honour are
registered against the rows that will: a run that used an unprotected connection must say so, owed by
I3, and a controller that refuses a protected one is a finding about the forest, owed by E1.

Branch C's write half followed on 2026-08-12, and it is the one that ends the run of libraries with
nothing to write to. **Nine rows now carry dispositions** — C1, C3, C5, C10, C11, C12, C15, and
capture's two writers B9 and B10 — decided together at
`S-15` and bound to the inventory by a test: eight Rebuild and one
Delete. What a bundle holds is documented at
[`what-a-bundle-holds.md`](../evidence/what-a-bundle-holds.md), bound by a test that
compares the document against the tables SQLite reports in a real database rather than against a
list in the code, so the two cannot be wrong together.

**The seal is the load-bearing part**, and it is recorded at
`0019` because
[`0003`](../decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md) has depended on it since
it was accepted while the mechanism did not exist. Three things came out of re-deriving it rather
than inheriting it. It is a **seal and not a signature**: there is no key anywhere in this product,
so it proves the bytes have not changed and proves nothing about who produced them. A **malformed
seal is `Unreadable` and not `Absent`**, because *something happened to the seal* is nearer the
opposite of *nobody ever sealed this*, and a failure rendered as a benign absence is the one defect
an audit tool cannot have. And the **cached verdict is gone**, because a cache whose function is to
avoid performing an integrity check is a way for the check to silently never run — the cost of
re-hashing a large bundle is real and is owed to C4 rather than waved away.

**What stops a half-written bundle being read as a whole one is a name, not a check.** A run writes
`evidence.db.partial`; renaming it to `evidence.db` is the last act, after the write-ahead log is
folded back in and after the seal is written. A check has to be remembered at every place a bundle
is opened. A name has to be remembered nowhere.

**Re-analysis does not come across.** It ended in a fresh seal rather than a verification, so a
re-analysed bundle could no longer prove what it was when captured, and nothing told the customer
which kind of evidence they held. What it was *for* — applying a changed rule catalogue to a forest
already read — is worth keeping and is a different shape, and is owed to D1.

**Nothing still runs, and branch C did not change that either.** The bundle writer has no caller:
capture can read a partition and the bundle can store one, and nothing joins them, because the
mapping between capture's types and the bundle's belongs to whatever drives a run. So gate 5b stays
blocked and its trigger stays on B20 for the third time. This is also where a forecast was found
wrong and corrected rather than quietly fixed: the surface register expected B9 to consume
`CapturedObject`, and B9 cannot see it — the bundle sits below capture and may not reference it.
That is `F-S15-6`.

**Where a run is kept was settled by the owner on 2026-08-12**, and it is recorded at
[`0025`](../decisions/0025-the-run-library-is-a-managed-root.md) and
[`0026`](../decisions/0026-one-answer-to-whether-runs-may-be-compared.md), with the reading behind
them at `S-17`. The tool owns one root directory and the operator chooses
where it is, because the predecessor hardcoded that location into two constructors and a tool that
decides for itself where several gigabytes of evidence go is a tool that fills the wrong disk. There
is no second tier, no capture to an arbitrary path, and no registering an outside bundle - that last
option is the only one that can hold a catalogue entry pointing at a bundle which has moved or been
deleted. A baseline belongs to a forest, and it needs no second axis for coverage — though not for
the reason `0025` gave, which is the subject of the next paragraph.

The same session settled how the product reports a comparison it cannot make. The predecessor
answered *may this run be used* in five independent places that disagreed, and the visible cost was
on the first screen a customer reads: a comparison refused as incompatible returns empty deltas, so
the dashboard printed **No changes since the previous audit** for a comparison the system declined
to perform, and rendered it as a pass. That is gate 4 - *found nothing* and *could not compute*
rendered identically - reappearing above the type system where the gate cannot reach. One component
now answers the question, the answer is a closed set of outcomes so the compiler names every
unhandled door, and the drift card takes one of three shapes with only the fully compatible one
permitted to say that nothing changed.

**Both of those records rested on a mechanism that had already been removed, and the next session
caught it before writing code.** `0025` and `0026` reasoned from the attestation ladder — the rule
that an operator excluding part of the directory had to state whether it was populated or empty, and
have the claim checked. `0017` deleted all of
it eight days earlier and said so; inventory row B3 says the attestation has nothing left to falsify.
Four of the eleven drift states therefore described situations no run could reach, and a document
binding them would have passed while asserting the impossible. The replacement is
[`0027`](../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md): coverage
varies only when a domain could not be fully read, or when the forest itself changed shape. A
partially read domain counts as failed, a run that failed one is refused a comparison and denied a
baseline, and a forest that gained or lost a domain is compared with a qualification rather than
refused. `0026`'s structure survived entire and only its table changed, which is the property it
said the closed set was buying, tested for the first time.

F1, F2, F3, F6, F9, F10 and F17 are **built**, and documented at
[`S-18`](S-18-run-identity-and-comparability.md): the run's two identities, the one lifecycle
vocabulary, what a run actually read, and the single verdict on whether it may be used. The states
and outcomes are bound to the code in both directions, and each card shape is checked against the
shape the code produces, so the document cannot go on calling a refusal qualified after someone has
changed it. Two more records came out of it. [`0028`](../decisions/0028-one-run-state-vocabulary.md)
replaces four disagreeing vocabularies with six words, **each arrived at from something observed** —
which the bundle could not support, because a failure, a cancellation, a reboot and a live capture
all leave an identical partial file. So [`0029`](../decisions/0029-a-run-that-ends-badly-says-so.md)
adds a run-outcome file written only when a run ends badly, and answers *is this run alive* by asking
whether anything still holds the partial file open — a question the operating system answers for
free, and one that needs no cleaning up after a crash. `0029` also restates the partial-file rename
rule, which had been stranded in `0019` under a supersession marker that `0020` never made good.

**One of these three is still true, and the other two were checked in September and are not.**
`RunComparability` has no caller, because the library, the drift card, compare, acceptance import and
baseline marking do not exist — that stands. `RunOutcomeFile.Write` **does** have a caller:
`CaptureRun.End` writes the file on every path that ends a capture badly, so a failed run reports
`Failed` and a cancelled one `Cancelled` rather than interrupted. And F6's read half is **built** —
`BundleReader` rebuilds a `DomainCoverage` per declared domain and returns a `RunScope`, whose own
summary is *"read back out of its bundle."* The one absent piece, a reconstructed `CoverageId`, is
refused deliberately rather than unbuilt, because the domains behind the hash are not in the `bundle`
row. Both stale claims described seams built after they were written and never re-read; the reasoning
is `P-27`.

**The decision records were read against each other for the first time on 2026-08-12**, and the
snapshot is at `POINT-IN-TIME-REVIEW.md`, with what the cross-reading
found at `S-19`. It is the document to read after time away: it
says what the product does today, what each of the thirty records decided in one line, which have
been overtaken and by what, and what is built against what is only agreed. **It has moved to
`docs/history/` and is no longer the thing to read after time away** — it was
a hand-maintained summary of the records, and by 2026-08-14 it predated five of them and miscounted
the production files. [`docs/DECISIONS.md`](../DECISIONS.md) replaces it and is generated, so it
cannot fall behind. `PointInTimeReviewTests` went with the other checks that held one document
against another.

**It found what it was commissioned to find, and the finding was customer-facing.** Five accepted
records described the bundle as **signed** — including the product's own identity sentence in
`0009` — while
[`0020`](../decisions/0020-the-seal-detects-corruption-not-tampering.md) had already established
that there is no key anywhere in this product and the seal proves only that the bytes have not
changed. Two slice documents repeated the claim to a customer, in the sentence justifying the
credential-attribute guard. `0019` said it in one
line — *"It is called a seal and not a signature, because it is not one"* — and `0019` is the record
a reader is told to move past. The owner withdrew the word on 2026-08-12 and it is recorded at
[`0030`](../decisions/0030-the-product-produces-sealed-evidence-never-signed.md). Every decision in
the five records survives; only the word moved. Their `## Decision` sections are corrected in place
and their `## Context` sections keep the reasoning that produced the error, per
[`0032`](../decisions/0032-a-decision-record-is-corrected-in-place.md).

**Every finding from the review is now closed.** `0007` kept
the assessment mode in the bundle partly because *"compare refuses to compare runs whose modes
differ"*, and nothing in the rebuild had an assessment mode while the closed set of comparability
outcomes had no member for one — the same sequencing error
[`0027`](../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) caught. The
owner ruled that there is no assessment mode and
[`0031`](../decisions/0031-there-is-no-assessment-mode.md) supersedes `0007` entirely.
`BundleLayout`'s remarks argued that a running run and an interrupted one cannot be told apart,
which [`0029`](../decisions/0029-a-run-that-ends-badly-says-so.md) decided two days later that they
can and `RunStateReader` implements; the paragraph is rewritten and says it previously argued the
opposite. And a bundle's file names had two owners, which the concept registry had no entry for and
gate 2 therefore could not see: `OutcomeFileName` moved to `BundleLayout`, the registry gained a row
for the concept, and the guard was mutation-tested both ways.

**What the review cannot do is stated in it.** A test can hold a document to the records; it cannot
notice that two records contradict each other. The `signed` contradiction was found by a person
reading thirty documents in one sitting, and no gate in this repository would have found it.

**Storage is where the rebuild currently stands, and C1 is deliberately unfinished.** The session
that was to rebuild the evidence schema did its reading, read the predecessor's write path rather
than the map's summary of it, and stopped without writing a schema. What it found is at
`S-20`. Two of the design's stated justifications did not survive
the reading: [`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md) credits the
typed-column shape with a production performance measurement that was taken against a **different**
shape — the predecessor stored 21 columns of *interpreted* data, not 29 columns of raw values — and
inventory row C1 instructs adopting a **deleted flag that capture never reads**, which would be a
column that is false on every row of every bundle forever — a field that looks like an answer and
measures nothing, which is the failure this repository has agreed to stop for.

The reading also **retracted a claim this session had itself made**. The predecessor's re-analysis
works, and `DerivedAnalysisPipeline.ResetForReanalysis` shows why: the captured-versus-derived
boundary the rebuild wants already exists in the old product, as an unnamed string array of eight
tables. Everything the owner used re-analysis for rebuilds correctly from `fact_ace` and
`dim_object`. What cannot be recomputed is narrower than was claimed — only where the source value
was **binary and was digested at capture**, which is why resource-based constrained delegation is
recorded as present with no record of who can use it.

Six questions are with the owner, and the one they hang from is whether the bundle is split into a
captured layer and a derived layer with an enforced boundary. The question of whether raw security
descriptor bytes are kept is **waiting on a measurement rather than an argument**:
[`Measure-DescriptorCost.ps1`](../../next/tools/Measure-DescriptorCost.ps1) reports how many
*distinct* descriptors a forest holds, because most objects share byte-identical inherited ones and
a deduplicated table may cost a fraction of one blob per object. It needs a production forest; a lab
will flatter it. **Nothing in `SecureAD.Evidence` was changed, and C1 still reads
`Decided, rebuilding after review`.**

**All twelve were settled on 2026-08-12, and the reason the last one changed is a defect in the
predecessor nobody had found.** The measurements came back from a production domain, and they
inverted the question: parsed access control entries cost **4.81 GB per 100,000 objects** stored per
object and **1.24 GB** deduplicated, while the raw descriptor bytes they were parsed from cost
**0.63 GB** deduplicated — the raw form is *smaller* than its own parsed form, and keeping it adds
about 13%. So descriptors are stored once per distinct descriptor with objects referencing them,
entry sets are stored once rather than once per object, and the raw bytes are kept.

**Inherited entries are now stored, reversing a decision from 2026-03-16.** The predecessor skipped
them to save 80–90% of the database, on the recorded grounds that *"control edges, findings, and
escalation paths only need explicit ACEs."* That claim is false as implemented, and `F-S20-14`
carries the evidence: containment is modelled **nowhere** in derivation — `parent_guid` reaches only
the object-detail read path, `dn_reversed` only the grids — so a principal granted control on a
container produced one edge to the container and none to anything beneath it. Paths through a
container into its contents never existed, and `affected_path_count`, the number that makes
chokepoints worth having, was computed from them. The grant was always reported; the consequence
never was. Storing inherited entries makes the graph correct by construction, and **owes D7 the
suppression of expected grants** or it drowns in edges from `Domain Admins` and `SYSTEM`.

**A production domain also returned one object in five with no readable security descriptor** — a
single sign-on product's per-user credential objects, read by an ordinary account, confirmed as a
permissions boundary rather than a lossy read by re-querying two hundred of them individually. That
is a coverage state [`0027`](../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md)
has no word for: the domain was enumerated completely while permissions were unreadable across a
fifth of it. Unreadable descriptors are now recorded positively, per object and as a run total.
**Whether such a run may serve as a baseline is the largest question left open.**

**Nothing in `SecureAD.Evidence` has been changed yet.** C1 still reads
`Decided, rebuilding after review`; what changed is that it now describes a shape derived from
measurement, and no longer instructs a session to adopt a deleted flag that capture never reads.

**The architecture itself has not been challenged, and that is now being fixed.** Every inventory row
asks *port, rebuild, delete or defer* — four answers to *what happens to this component*, none of
which ask **whether the component should exist**. `0033` says nothing inherited is definitive, and
that scepticism has been applied to the predecessor's contents but not to the shape they sit in.
`F-S20-14` is what made the gap concrete: a defect invisible from any single component, found only
because someone asked why a decision had been made.
`DESIGN-challenges-to-the-inherited-shape.md` records
five challenges — two supported by measurement, three explicitly opinion — and
`sessions/S-22` is the review that reads the
analytical half of the previous product: derive, rules and findings, and compare. That is the half
nobody has read. Every statement this rebuild has made about those stages so far comes from the
schema they write rather than their code, which is stated as a limitation in `S-20` rather than
hidden — and it is the limitation that let `F-S20-14` go unnoticed. Both documents are proposals.
**Nothing in them is decided and nothing is built.**

**That half has now been read, and three of the five challenges moved.** The reading is at
`S-22-what-the-old-app-does-with-the-data.md` — 42
files and 12,315 lines of the predecessor's derive, rules and compare code, nine things checked and
found correct, eleven findings. **Challenge 4 is confirmed and is now the highest-ranked of the
five**, because the Tier 0 definition turned out to be wrong in a way nobody had proposed: the
customer's own `tier-policy.json` reaches the asset tier screen and **never reaches the escalation
search**, so *who can reach our certificate authority* answers nothing, confidently. **Challenge 1
did not survive.** It was the one marked *arithmetic rather than taste*, and the arithmetic describes
a shape the predecessor does not have — the reverse breadth-first search it proposes is already
implemented, and the path table is capped at twenty per principal rather than growing
combinatorially. Its text is left unrevised for the owner. **Challenge 3 is strengthened** — the
evidence blob is not merely a rendering, it is how two pipeline phases pass data to each other, with
a parser that drops what it does not recognise and does not count it. **Challenge 5 is partly
refuted**, its named risk already handled and the residue inverted.

Three defects are customer-facing and none is being fixed, because the predecessor is frozen: a
crashed escalation phase renders as **no escalation paths** rather than as a failure; a domain whose
permissions were skipped is reported as **fully covered**; and a `Deny` naming a group is invisible,
so the product reports control that Windows would refuse. Each is recorded against the rebuild row
that owes it. **Four questions are with the owner**, the largest being whether a comparison across a
changed Tier 0 definition should be refused or qualified — a door `0026` and `0027` both leave
unwatched, which is the second time that sequencing error has arisen.

**What capture must read has now been derived from the rules rather than from the port** —
[`S-23-what-capture-must-read.md`](../audit/the-attribute-catalogue.md). The catalogue's consumer gate
accepted only an inventory row, and almost no inventory row is built, so the catalogue was bounded by how
far the port had got rather than by what the product needs. A `Read by` cell may now name a **rule
card**, and derived against all sixty-two, the catalogue was three attributes short. Those three
made **SEC-091 and SEC-092 unanswerable** — both enabled, both reporting a clean forest whatever the
forest looked like, which is the one thing an audit tool must not do. `operatingSystem` and the two
LAPS expiration timestamps are captured on the owner's decision; the catalogue is **version 2**; and
a LAPS password value is never requested, held by a guard rather than a sentence. The union costs
under a megabyte per 100,000 objects, which settles the general point: storage is not the argument
against an attribute. Six captured attributes have **no rule consumer at all**, `msDS-KeyCredentialLink`
among them — a gap in the rule catalogue, not in capture — and six rules need SYSVOL, which nothing
in the directory can answer.

**The bundle schema was rebuilt at C1** — `S-24-the-audit-database-schema.md`,
in progress. Two governing documents described different schemas: `S-16` — the retired slice, since
consumed into [`what-a-bundle-holds.md`](../evidence/what-a-bundle-holds.md) and
[`the-bundle-on-disk.md`](../evidence/the-bundle-on-disk.md) — listed a row per object per
attribute and [`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md) replaced that with
typed columns the following day, and the committed code implemented the shape that was replaced.
`0022` governs — not because it is newer, but because `S-16`'s table pair rested on a distinction its
own mechanism does not record: `completeness = NotReturned` is provably identical to *has no values*.
`0022`'s **stated reason** was nonetheless wrong, and the real one is stronger — Active Directory
omits an absent attribute without saying why, so which it was is not observable at capture at all.
`what-a-bundle-holds.md`, `0022` and the schema now agree: an object is one row of typed columns derived from
`CapturedAttributeCatalog`, each multi-valued attribute has a table to itself, and **nothing anywhere
records why a value is missing.**

Two things fell out of checking that against Microsoft's documentation rather than against the
repository's memory of it. `F-S7-27` — open for a week, and inherited by three documents — was a
**misreading and is now resolved**: bit 128 of `searchFlags` is *ignored* on a base-schema attribute,
not forbidden, so the attribute that looked like a counter-example never was one. And a new
**breaks-for-user** finding, `F-S24-1`: the `Signed` rung of the connection ladder is unencrypted and
requires no declared allowance, while a **Windows Server 2025** controller silently strips
confidential attributes from an unencrypted search and returns no error. The gated rung fails loudly
on such a controller; the ungated one succeeds and misleads. Sealing becomes the automatic line,
owed by **A2**, and the bundle will record the connection security level each controller was read
over, owed here.

Building the schema turned up more. `F-S24-6`: the range-retrieval refusal used to happen twice
and now happens once, the constraint having lost the column it was checked against — the surviving
wall is the stronger of the two, but the redundancy is gone until a capture-to-evidence converter
restores it. `F-S24-7`: removing the object's completeness field left `EvidenceObject` unable to
vouch for itself under gate 4, and **the build is left failing on that check** rather than widening
an allowlist whose own comment forbids it.

And a finding that was raised, argued in detail, and then **withdrawn as false**. `F-S24-5` claimed
a null column could also mean *capture never asked this class for this attribute*. Reading the
pipeline rather than the documents disproved it: `CaptureSearchRequestFactory` adds
`CapturedAttributeCatalog.All` to every request and `PartitionCapture` walks the same full list for
every entry, so **every object is asked for every catalogued attribute whatever its class**. The
schema's union-of-all-classes column set is the exact mirror of that request, not a compromise.
What the mistake uncovered is real and is now `F-S24-8`, **repaired the same day**: the catalogue is
*written* as a per-class table, and the method that read as the request scope has been renamed
`AttributesJustifiedBy` and now says outright that it does not decide the request. `All` says that it
is the request, and why a per-class one is impossible in a single pass — an LDAP search names its
attributes before the object's class is known, so scoping by class means one paged search per class
per partition. A test asserts the request against the factory that builds it, so a class-scoped
request now costs a deleted test rather than an edit. `F-S24-9` follows from the same fact:
`CapturedObject.Completeness` is `SomeAttributesDidNotArrive` for essentially every object ever
captured, which is a constant rather than a signal.

**C1 is finished** — `S-25-the-finished-schema.md`. The
security-descriptor half `S-24` left untouched is rebuilt: descriptors are deduplicated on a
cryptographic hash of their bytes with their raw form stored beside them, entry sets and parse
errors are held once per descriptor rather than once per object, and objects reach them through a
link table — the shape C1 measured at 4.81 GB down to 1.24 GB per 100,000 objects. **An object whose
descriptor could not be read now has a row saying so**, which is the part that is not merely size:
on a production domain that was 19,927 objects in 100,000, and they were indistinguishable from
objects that grant nothing. The count is kept per partition, so the run total is a sum over the
evidence rather than a second number beside it.

`F-S24-7` is repaired the way it was decided: `EvidenceObject` carries the coverage it was read
under, which both removes the state where an object and its partition could disagree and lets the
type answer gate 4 from the one place the answer is real — **the build is green on all 887 tests**.
`F-S24-1` option C landed: every coverage row records the connection security level its partition
was read over. `PartitionCoverage` and `PartitionCoverageRecord` became one type per
[`0035`](../decisions/0035-coverage-is-recorded-once-per-capture-unit.md), and the configuration and
schema partitions gained a run-level home, so a run that never read the schema partition now fails
instead of reporting every domain as covered.

Three findings are worth carrying forward. `F-S25-1`: `page_size` is silently ignored once the
database is in write-ahead logging mode, not only once a table exists — a pragma that fails by doing
nothing, found by mutation. `F-S25-2`: C1's account of the predecessor's constrained reason set was
right about the defect and wrong about its cause, and the two imply different repairs. And
`F-S25-5`: **the documentation disagreement is wider than any one row**. Five documents were caught
disagreeing with the code during this session alone, each by a binding test — which is the mechanism
working, and also its limit, since only bound documents are covered and `F-S24-2` already showed a
binding cannot detect that both sides describe a superseded design. A sweep is owed as its own
session.

**The sweep happened** — `S-26-reconciling-the-documentation.md`.
Eight corrected decision records were read against every document citing them, all 256 inventory rows
against what is actually built, and the governing documents against the accepted decisions. **Six
disagreements, five of them the document and one the inventory. None was the code**, so nothing was
handed to a row and no production file changed.

The one that matters is `F-S26-1`: `S-17`'s retraction of the attestation ladder stopped one bullet
short, leaving `CoverageId` described as hashing the applied OU exclusions — which the rebuild's
`CoverageId` has never done and has a reflection test forbidding. That is `F-S24-2`'s shape caught
one step earlier, and it was found by reading the decision before the document and the document
before the code, in that order, by a person. No test in this repository would have found it, which
is the limit `F-S25-5` named and this session did not remove.

What it did remove is the invisibility. **Six new bindings**, each mutation-tested in both
directions: `S-17`, `S-19`, the historical records, `READING-ORDER.md` and the `DESIGN-` notes, the
inventory's own citations, and the session register. Two of them caught this session's own mistakes
within minutes of being written — a binding aimed at the wrong documents, and an inventory row
"corrected" from something true to something false. Also recorded: `0034` had no inventory row
(`F-S26-2`), and `S-21` — the parser read against Microsoft's specification, the one review the
golden hashes cannot stand in for — was written and never run, with nothing saying so (`F-S26-6`).

**`S-21` then ran** — `S-21-the-security-descriptor-parser.md`.
The parser read against `[MS-DTYP]` and `[MS-ADTS]` rather than against its own tests, because its
own tests cannot answer the question: the golden hashes and canonicalisation fixtures were computed
from the predecessor, so they prove **fidelity**, not **correctness**, and a misreading inherited
from the old parser passes all of them. **Six discrepancies. Two repaired, four findings, no golden
value touched.**

Eleven claims came back verified against the specification, including the six-byte big-endian SID
authority, the conditional object-ACE GUID order, and the AD DS generic mapping bit for bit. The
repairs were the two the specification decides outright: the four self-relative offsets are `ULONG`
and were read signed, so an offset above `0x7FFFFFFF` went negative, passed the bounds check and
**threw out of a parser whose whole contract is to record damage rather than raise it** (`F-S21-3`);
and an owner offset past the end was dropped in silence, reading as an object that records no owner
rather than one whose owner could not be read (`F-S21-4`).

**Two open findings can change a permission the product reports, and both are owner decisions.**
`F-S21-1`: a DACL whose entries fail to parse is reported `Empty`, which in Windows means
deny-everyone — so an object the product **could not read** is presented as the safest in the forest,
and carries an `ace_set_hash` over nothing. `F-S21-2`: normalisation sorts into canonical order and
keeps no original ordinal, so a non-canonical DACL — an allow placed before a deny, which is what an
attacker leaves behind because tooling reports the deny while Windows honours the allow — can
afterwards be neither detected nor evaluated. Also raised and owned by nobody: **the SACL is never
parsed**, while `ParsedAce` promises DACL or SACL.

**All three were decided the same day, and built.** [`0036`](../decisions/0036-capture-never-requests-the-sacl.md),
[`0037`](../decisions/0037-an-unreadable-dacl-says-so.md) and
[`0038`](../decisions/0038-a-descriptor-records-whether-its-dacl-was-canonical.md).

`DaclState` gains **`Unreadable`**, and a `DaclCompleteness` outcome sits beside it, because a fourth
state alone does not catch the worse half: a DACL that yields three of the five entries it declared
is genuinely `Present`, and a missing allow entry there is a permission the product never reports.
Every descriptor records **whether its DACL arrived in canonical order**, judged during the parse
while the entries are still in arrival order — the per-entry ordinal `S-21` offered was withdrawn
rather than deferred, because `raw_bytes` was already in the schema and re-parsing recovers exact
order, so an ordinal column would have duplicated evidence the bundle already holds. And capture
**never requests the SACL**, which was always true and is now decided: the mask is restricted so a
capture runs as an ordinary authenticated user and nobody has to grant an audit tool a privilege on
their domain controllers. `0036` names what that costs — audit misconfiguration is out of scope.

**Gate 4 improved one of the three and caught a bug in it.** `0037` first asked for the declared
entry *count* to be stored. The gate refused a bare `int` on sight and was right: a header declaring
zero entries and a header too truncated to read would both have reached a caller as `0` — the
record's own defect, one field over — and the first draft really did report a truncated ACL header
as an empty DACL. The count became a closed set of outcomes, and `0037` is corrected in place to
record that its own first draft reproduced the failure it exists to remove.

`SESSION-LOG.md` stays in `docs/review/` and covers both codebases. It
is the owner's narrative of the product, not of a folder layout, and the interleaving is the honest
record of a period when both existed.
