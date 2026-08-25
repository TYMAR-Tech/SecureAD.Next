# The rebuild

**This is the authority for this repository.** It states what counts as documentation here, the
gates every change is held to, and how a session continues the work. The root
[`README.md`](../../README.md) is a signpost to it and nothing more.

The product is being rebuilt under [`next/`](../../next/), which builds from
`next/SecureAD.Next.sln`. Per
[`0013`](../decisions/0013-the-bundle-is-no-longer-a-two-way-contract.md) the `audit.db` bundle is
no longer a contract with the predecessor: the rebuild writes whatever schema it needs and the old
application is not expected to open it. The predecessor is a **separate repository** and is not
here; documents that mention it are recording history.

## What is built, and what is not

Measured 2026-08-24: 28 layer documents carrying 392 capability rows, each naming a test that
proves it.

**Built.** Finding the forest without anything being typed in; connecting up an ordered ladder of
protection and recording which rung each controller answered on; proving a controller at preflight
before a run commits; capturing objects, permissions and Group Policy files into a bundle that is
sealed when the run completes, with its coverage and any deliberate exclusion recorded inside it;
and reading that bundle back offline through the run library, a captured directory tree and one
object's detail.

**Not built.** Findings and rules — nothing in this tree produces a finding, and per
[`0045`](../decisions/0045-the-shell-is-built-before-the-judgement-half.md) screens bound to
findings are left out rather than stubbed, so a customer is never shown an empty result that reads
as *nothing is wrong*. Also unbuilt: effective access evaluation, reports and export, and any
judgement about Group Policy — the parsers read `Registry.pol`, security templates and Group Policy
Preferences, but nothing decides what any of it means.

**Start at [`ARCHITECTURE.md`](ARCHITECTURE.md)** if the question is *how is this put together* —
the stages a run passes through, the projects they live in, and which project may use which. It is
bound to the real project references in both directions, so a stage that says *not built* says so.
This file is about how the work is done; that one is about what is being made.

## Where to look, and what each place is allowed to say

Reorganised 2026-08-14, because the same fact was written in too many places to keep them agreeing,
and again on 2026-08-24 when the layer documents replaced the per-component ones and three folder
READMEs were folded into this file. See §`One fact, one home` below for what was measured and why.

| Question | Where | What it may contain |
|---|---|---|
| What does this component do? | [`docs/layers/`](../layers/) | One document per component, written from the code and bound to it by a test. **This is the description** |
| What can an operator do? | a capability row on the layer document that owns the subject | A sentence naming the test that proves it. The test is the evidence; the row is the index |
| What has this product decided? | [`docs/DECISIONS.md`](../DECISIONS.md) | **Generated.** Never edit it; run `next/tools/Build-DecisionIndex.ps1` |
| Why was it decided that way? | [`docs/decisions/`](../decisions/) | The reasoning. **The only place a decision is stated** |
| What may need doing? | [`docs/PUNCH-LIST.md`](../PUNCH-LIST.md) | Open work, findings without a decision, and what blocks each |
| Which document owns a type? | [`SURFACE-REGISTER.md`](SURFACE-REGISTER.md) | Every public type and its one owning document. Generated against the assemblies |
| What rules did the predecessor have? | [`docs/rules/`](../rules/) | One card per `SEC-*` rule of the **old** application, kept as reference for rebuilding them. Not documentation of this tree |
| What has nobody consumed yet? | [`docs/areas/`](../areas/) | An input to the rewrite, not a fixture. Emptied as its content is moved; the folder retires with the last file |
| What did somebody find on a Tuesday? | the archive, outside this repository | Dated narrative. **Never read to find out what is true** |

The split between the fourth row and the last is the one the tests already implied: **a document
named for a thing is documentation; a document named for a session or an activity is history.**

### The rule cards, and the standard they are held to

`docs/rules/` is a **permanent reference, not a review**: the per-rule audit that created it is
finished, and a rule and its card change together. Two files in there do work the cards cannot:

- `FIRST-PARTY-VERIFICATION.md` is a claim-level ledger — each atomic fact a rule depends on
  (GUIDs, access-mask bits, SID and RID values, UAC flags, baselines) verified **once** against a
  first-party Microsoft source and mapped to every rule that consumes it. When a Windows version
  changes a value, that ledger is what lists the rules to re-check.
- `IMPROVEMENTS.md` carries the cross-rule backlog and the `[IMP-*]` tags referenced from code
  comments.

**The guiding principle is "trust no doc".** A claim counts as verified only when the cited
Microsoft page actually states the value. Internal consistency is not correctness — every
implementation in a codebase can agree with the others and still be wrong. That is the same lesson
`F-S44-2` records at the top of the instructions, arrived at independently.

A card's `Reviewer` row records who verified it once. It is not a claim about who maintains it now.

### Writing a decision record

Folded here on 2026-08-24 from the decisions folder's own README, which also carried a hand-maint
index of every record — a second copy of the generated [`DECISIONS.md`](../DECISIONS.md), and
exactly the duplication this consolidation exists to remove.

**A decision record answers *why*.** It is not a bug report, a design document, or a task. If you
find yourself writing what is broken, that is a finding and belongs in
[`PUNCH-LIST.md`](../PUNCH-LIST.md). If you find yourself writing how the system behaves today,
that is a description and belongs in the layer document that owns it.

Write one when a choice was made that a later reader could reasonably second-guess, and where the
reasoning is not visible from the code. A decision obvious from reading the code needs no record.

- **Corrected in place**, per [`0032`](../decisions/0032-a-decision-record-is-corrected-in-place.md).
  When a later decision changes a record, `## Decision` and `## Consequences` are edited to say the
  right thing, because both are claims about what holds now. `## Context` is left as written and the
  superseded claim marked inline where it sits, because a wrong *why* is evidence of how the error
  entered. **Git is the history** — `git log -p` retrieves any prior version, so editing destroys
  nothing.
- **The test is: would a grep hit on this line, with no surrounding context, mislead someone?** If
  yes, the line changes.
- **Supersede only when a whole record goes.** Write a new record and set the old one's status to
  `Superseded by NNNN`. Both stay. A blanket marker over a record that is partly right is how
  `0019`'s rename rule was nearly lost, so **a supersession marker says where each part went**.
- **Never delete a record, and never reuse a number.**
- **Nothing inherited is definitive**, per `0033`. The predecessor's code and documentation are
  evidence to be checked, not answers to be adopted.
- **One decision per file**, named `NNNN-short-slug.md`.
- **Keep it under about 40 lines.** A long one is usually two decisions, or a design document
  wearing a decision's clothes.
- **Do not cite finding numbers.** They route review sessions and mean nothing to a reader outside
  one. State the fact, not the ticket.

```
# NNNN - Title stating the decision, not the topic

Date: YYYY-MM-DD
Status: Accepted | Superseded by NNNN

## Context
What was true that forced a choice.

## Decision
What was chosen, in the present tense.

## Consequences
What this makes cheap, what it makes expensive, and what it forbids.
```

**What no test holds:** whether any of that content is true of the code. See §`How to continue this
work` for what `DecisionIndexTests` does and does not check.

### Where the rebuild tree's own conventions live

Folded here on 2026-08-24 from the rebuild tree's own README.

`next/` builds from its own solution, `next/SecureAD.Next.sln`, and inherits `Directory.Build.props`
(nullable, implicit usings, version stamp, analyzers), `Directory.Packages.props` (central package
versions), `global.json` and `.editorconfig` from the repository root rather than restating them per
project. The project list and the layering rules are in [`ARCHITECTURE.md`](ARCHITECTURE.md), which
is bound to the real `.csproj` references in both directions.

**Why the target frameworks differ, which is load-bearing.** `SecureAD.Kernel` and
`SecureAD.Evidence` target plain `net10.0`, not `net10.0-windows`. The predecessor's
`SecureAD.Core` targets `net8.0-windows` for no reason its contents require — its parser,
catalogues and DN helpers use only `BinaryPrimitives`, `FrozenCollections`, `Cryptography` and
`Text`. That loose target is how presentation-shaped types came to live in the domain project.
Targeting plain `net10.0` turns a convention someone has to remember into a compile error.
`SecureAD.Audit` is `net10.0-windows` only because capture uses
`System.DirectoryServices.Protocols`, which is a reason about LDAP rather than about presentation.

**No live directory reads outside capture**, per
[`0008`](../decisions/0008-live-verification-is-removed.md).

## One library now, and what is left of the other

**`docs/` is this product's library.** [`docs/layers/`](../layers/), [`docs/decisions/`](../decisions/)
and this folder all describe the rebuild. That is a reversal: until the predecessor's documentation
was archived on 2026-08-20, `docs/` was the *old* product's library and `docs/next/` was the new
one. The sentence describing that arrangement stood here until 2026-08-24, long after it stopped
being true.

**The only part still describing the predecessor is [`docs/rules/`](../rules/)** — one card per
`SEC-*` rule of the old application, kept because the rules will be rebuilt and the cards record
what each one was for. They are **source material, not inheritance**: read the way you would read a
specification someone handed you, and nothing becomes this product's documentation by being copied
across.

That costs time, and it is the point. The old library was thirty-three thousand lines written
across a period in which the product's identity changed twice, and it held six kinds of claim that
were true when written and are not now. Copying it forward would carry those in without anyone
deciding to.

### The one exception

**Decision records stay in [`docs/decisions/`](../decisions/).** They are dated r
choices made on a particular day with the reasoning as it stood. A record wholly replaced is
superseded; a record partly overtaken is **corrected in place**, keeping its `## Context` section as
written so the reasoning that produced the error survives. Git is the history. See
[`0032`](../decisions/0032-a-decision-record-is-corrected-in-place.md), which replaced an
append-only rule that put corrections at the top of a file where `git grep` could not see them.

They are reviewed rather than inherited. Each existing record is read and either confirmed as still
binding on the new product or superseded by a new one.
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
[`what-a-bundle-holds.md`](../layers/evidence/what-a-bundle-holds.md) to them, so a twelfth table fails
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
already had — a component document said the capture entry point takes a destination, `0025` decided
two days later that it does not, and two other files had copied the first.

So:

- **A decision is stated once**, in `docs/decisions/`. Everything else cites the number and does not
  paraphrase the reasoning.
- **The index over the records is generated**, at [`docs/DECISIONS.md`](../DECISIONS.md), by
  `next/tools/Build-DecisionIndex.ps1`. Never edit it; regenerate it.
- **Session narratives are history**, archived outside this repository, and are never read
  to find out what is true. **That rule was broken inside this file**: a 502-line `Status` section
  narrating one session after another stood here until 2026-08-24, claiming three times that nothing
  still runs while the shell shipped and captures worked.

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

Where a source of truth exists for what a rule was meant to do — `docs/rules/`, which describes the
**predecessor's** rules — the assertion comes from there rather than from whatever the old test
happened to check. Those cards are evidence about the old product, not a specification of this one.

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
| 4b | A member carrying a vouching *name* and a value that cannot vary | The vouching member must be reachable as both values: the gate drives each type's own public constructors and factories, and fails a boolean voucher it only ever saw say one thing | **done** — `VouchedValueReachabilityGateTests`, closing `P-63`. It reads nothing under `next/tests`, so a test can neither satisfy it nor break it. A cheaper check on the getter's IL is carried beside it, for the vouchers the driver cannot build. Four are named as beyond its reach, each with a reason, and a decay test deletes an entry the driver later learns to settle |
| 5a | Dead surface accumulating unnoticed | Every public type is listed in [`SURFACE-REGISTER.md`](SURFACE-REGISTER.md), claimed by exactly one document. A type claimed by no document, or by one that does not exist, fails the build | **done** — `SurfaceRegisterTests`, with `TypesTableOwnershipTests` holding each page's `TYPES` table to the register so two pages cannot claim one type. Keyed to areas from 2026-08-16 and to layer documents from 2026-08-24, as the area files were consumed. The shell is exempt from the register and bound instead by `ShellLayerTypesTests`, because it exports nothing by design |
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
[`CONCEPT-REGISTRY.md`](CONCEPT-REGISTRY.md), and `UnvouchedResultGateTests` holds gate 4 while `VouchedValueReachabilityGateTests` holds gate 4b. Each
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

**The documentation is consolidated, and staying that way is the job.** One layer document per
component, written from the code and bound to it by a test; `docs/decisions/` for positions;
[`PUNCH-LIST.md`](../PUNCH-LIST.md) for work that may need doing; everything else deleted. A pass
that adds documents without removing any has not consolidated anything.

### Route every fact to exactly one destination

| Kind of fact | Goes to | What holds it there |
|---|---|---|
| What the code does | the layer document for that component, and a row in its `TYPES` table | that page's own component gate, plus `TypesTableOwnershipTests` and `SurfaceRegisterTests` |
| What an operator can do | a capability row naming the test that proves it | `CapabilityCitationTests`, `AreaFileGateTests` |
| A product position | a record in `docs/decisions/` | `DecisionIndexTests` — **the index only, never the content** |
| Work that may need doing | [`PUNCH-LIST.md`](../PUNCH-LIST.md) | `PunchListIdentifierTests` — the shape only |
| Anything else | deleted | — |

### The rules a session works to

Each says plainly whether the build enforces it, because a rule nothing checks is a rule that
decays and the point of this section is to stop that happening again.

1. **One type, one owner.** Adding a public type means adding a row to the owning page's `TYPES`
   table and a row to [`SURFACE-REGISTER.md`](SURFACE-REGISTER.md). Two pages may not claim one
   type. **Enforced.**
2. **A capability names a test that exists and passes.** The test is the evidence; the table is the
   index. **Enforced.**
3. **Nothing is deleted until its claims have somewhere else to live.** `AreaFileCitationSurvivalTests`
   reads deleted documents back out of git history and refuses a deletion that dropped a capability.
   That gate also makes recovery possible: seventeen run-library claims were restored verbatim from
   history on 2026-08-24 rather than rewritten. **Enforced.**
4. **Every path you write must resolve** — as a link, in backticks, or in a `<c>` tag.
   `DocumentationLinkGateTests`, `ProsePathCitationTests` and `DocumentPathCitationTests` cover
   those three between them, across the whole repository and not only `docs/`. If a document was
   deleted, take the backticks off so the sentence reads as history. **Enforced.**
5. **Measure before you plan, and say what you opened.** A count you did not read is not a
   measurement, and a probe that matches a substring is not a probe — `README.md` is a substring of
   six paths in this repository and that has produced wrong answers twice. **Not enforced.**
6. **Prove every new gate failing in both directions before believing it**, with a mutation harness
   that restores what it touched and verifies byte-identity by hash. Say which checks caught what,
   including the ones that did not fire. **Not enforced.**
7. **A floor is a decaying proxy.** If you are editing a threshold to make a gate pass, the
   threshold is the defect. **Not enforced.**

### What nothing holds, and you should know it

- **Whether a decision record's content matches the code.** `DecisionIndexTests` checks the
  catalogue is tidy — every record listed, every listing real, each with a title, date and status.
  It does not read a single word inside one. Measured 2026-08-24: of 77 records, 29 are named in a
  test, 53 in production code, and **23 appear nowhere in the tree at all**. Several of those
  describe behaviour that does exist.
- **Whether a capability sentence describes what its test asserts.** The gate closes the gap where
  a test was renamed, deleted or never written. It cannot read English.
- **Whether any of the prose is any good.** That needs a reader.

### Decisions are the owner's, and a session waits for them

Tooling, code layout, test structure and technique are the session's to settle. What the product
does, what it stores, what it tells a customer and what it refuses are not — those are presented
with the options and their costs, and the session waits for an answer before writing code. **A brief
saying "decide X" is not delegation of a product decision.** This is recorded here because it was
got wrong: a session was told to decide six open points, decided them, built to them, and four did
not survive review.

**Where a decision rests on what the old implementation did, read the old implementation.** It is a
separate repository and the owner will point you at it. Any summary of it written by an earlier
session names the file to open; it is not the evidence. Reading it first is what turned five open
Group Policy design questions into one on 2026-08-24 — four had already been answered in code years
before, and the fifth turned out to be an inherited defect rather than a decision to port.

**Record a decision when it is made, not at the end.** A session that batches its documentation is
one interruption away from losing all of it. If recording is deferred, say plainly that nothing is
written down yet, so it is the owner's risk to take rather than a silent one.


> ### The Evidence warning that stood here has been discharged
>
> This section carried a warning, dated 2026-08-13, that
> [`next/src/SecureAD.Evidence/`](../../next/src/SecureAD.Evidence) held writers superseded by
> review: no re-analysis path, and a seal framed as a tamper control. **Both were checked on
> 2026-08-24 and neither still holds.** Re-analysis exists across `CaptureRun`, `BundleSchema`,
> `BundleSealing` and `BundleWriter`; and `RunHash` now describes the seal as detecting corruption,
> naming the tamper framing in the past tense as the thing it corrected, per
> [`0020`](../decisions/0020-the-seal-detects-corruption-not-tampering.md) and
> [`0021`](../decisions/0021-re-analysis-produces-a-new-bundle.md).
>
> It is recorded rather than deleted because it stood for eleven days after it stopped being true,
> which is the failure this whole section exists to prevent. **A dated warning about current code is
> a claim, and a claim in the authority needs re-checking or removing, not leaving.**

## How a session is started

**Read this document, then measure before planning anything.** There is no prompt template and no
session folder: session briefs and narratives were archived on 2026-08-20 because they recorded what
one session intended on one day and never stated current behaviour, and several actively misled.

A brief handed to a session is an input, not authority — and it will contain wrong figures, because
every one so far has. **Re-measure everything it asserts.** The tools under
[`next/tools/`](../../next/tools) exist for that: `measure-rewrite-progress.ps1` regenerates the
queue from the tree, `show-area-file-types.ps1` reports who owns what,
`check-document-encoding.ps1` runs after any scripted edit to a document, and the `mutate-*.ps1`
harnesses are the shape a proof of a gate should take.

**Run the whole suite, never a filter.** A targeted run has passed 47 of 47 while the tree was
broken.

**Commit only when green**, stage by name rather than with `git add -A`, and reserve the last
actions of a pass for `git status --porcelain -uall`, `git diff --stat` and a zero-byte scan —
writing the summary from their output or not at all.
