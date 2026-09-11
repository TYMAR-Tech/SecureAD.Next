# Architecture

How the rebuilt product is put together: the stages a run passes through, the projects those stages
live in, and which project is allowed to use which.

This document owns project layering and dependency direction. The authoritative current and target
stage flow is [`WORKFLOW.md`](WORKFLOW.md); stage reachability is stated there once rather than being
repeated here and allowed to drift. Layer documents own behavior inside each stage.

> **The layering table below is description, not the rule. The rule is code.**
> As of 2026-09-12 the layers and permitted references live in `ProjectLayeringGateTests`, which
> enforces them against the project files. This document was the input to that check until `P-184`,
> which made it a test holding a document to the code — the shape the owner's rule of 2026-09-12
> forbids, because a drifting document is a documentation problem and is fixed by reading it rather
> than by a failing build. **Nothing now checks that the table below matches the one in the test.**
> If the two disagree, the test is right. Change it there, and correct this afterwards.

## What a run is

One run produces one **bundle** — a single file that is the complete evidence of a forest as it
stood at one moment. Everything the product ever says is said from a bundle, and nothing is said
from a live directory: per [`0008`](../decisions/0008-live-verification-is-removed.md) the only
component that touches a domain controller is capture.

That is the shape of the whole product, and it is worth stating plainly because it is unusual and it
is load-bearing. A screen showing a permission is not asking the directory. It is reading a file. So
a finding can be reproduced a year later, on a machine that has never seen the forest, and will say
the same thing — which is what makes it evidence rather than an opinion.

| # | Stage | What happens | Current state |
|---|---|---|---|
| 1 | **Discover and preflight** | Find the forest's domains and partitions, choose controllers, negotiate security and prove each planned unit before committing a run | Built |
| 2 | **Review and authorize scope** | Show included and unread scope and collect exact per-run exclusion attestations | Built in Shell; CLI has no interactive exclusion path |
| 3 | **Capture** | Read Configuration, Schema, included domains, objects, permissions, memberships and relevant SYSVOL data | Built |
| 4 | **Reconcile and seal Evidence** | Compare referrals with the authorized plan, persist uncertainty, refuse confirmed unplanned scope, and seal immutable Evidence | Built; Evidence schema 9 |
| 5 | **Derive reusable facts** | Compute offline cross-object facts into a disposable store beside Evidence | Built; AdminSDHolder products are bound, persisted and readable |
| 6 | **Judge** | Apply scheduled rules to declared Evidence/Derivation inputs and write a disposable judgement store | Built and reached by Shell; CLI orchestration does not yet invoke it |
| 7 | **Read and present** | Read the run library, coverage, objects, permissions and findings without contacting the directory | Built foundation; dashboards/reports remain incomplete |
| 8 | **Compare and export** | Compare compatible captures and produce durable reports or machine-readable output | Not built |

Capture is the stage that cannot be redone. A forest is only readable as it is today, so anything
capture does not collect is not a defect to fix in the next release — it is a forest that has to be
captured again. That is why capture's decisions get the scrutiny they do, and why
`S-8` exists.

## The projects, and which may use which

`SecureAD.Shell` is the WPF application an operator uses. `SecureAD.Cli` is the unattended host.
Their current and target orchestration are described in [`WORKFLOW.md`](WORKFLOW.md).

<!-- DEPENDENCIES:BEGIN -->

| Project | Layer | May reference | Owns |
|---|---|---|---|
| SecureAD.Kernel | 1 | - | What is true about Active Directory regardless of this product: security descriptors, permission canonicalisation, distinguished names, schema identifiers, and the single answer to whether a right is dangerous. Plus the two contracts everything else must adopt, `Result` and `AuditError` |
| SecureAD.Evidence | 2 | SecureAD.Kernel | The bundle: its schema, and reading and writing it |
| SecureAD.Audit | 3 | SecureAD.Kernel, SecureAD.Evidence | Capture and forest discovery. The only project permitted to open a connection to a directory |
| SecureAD.Derivation | 4 | SecureAD.Kernel, SecureAD.Evidence | The derivation store: what was worked out from a sealed bundle before any rule ran — group nesting, membership closures, and the identities a principal carries — written beside the evidence and never into it. It is a separate project from SecureAD.Judgement, and below it, because derived facts are an input to judging rather than a product of it: a rule will read this, and nothing here may read a rule, or a phase could quietly derive what one rule wanted rather than what the directory said. It is a separate *file* from the judgement store because the two have different lifetimes — a judgement is rebuilt whenever a bundle is judged, while deriving is the most expensive thing the product does and does not change when a rule does, so a bundle is derived once and judged many times |
| SecureAD.Judgement | 5 | SecureAD.Kernel, SecureAD.Evidence, SecureAD.Derivation | Executable rules and the judgement store: Judgement coordinates captured objects and reusable derived facts, then records what the rules concluded beside the sealed evidence. Evidence and Derivation do not reference it: capture must work with no judging present, and derivation must never see a rule or it could compute what one rule wanted rather than what the directory said. Judgement never references Audit and never contacts a directory |
| SecureAD.Cli | 6 | SecureAD.Kernel, SecureAD.Evidence, SecureAD.Derivation, SecureAD.Judgement, SecureAD.Audit | The command that runs a whole audit unattended. It reads a command line and calls `CaptureSession`, then `Stage2aRun.Derive`, then `JudgingRun.Judge`; every decision a run makes is made below it, per [`0039`](../decisions/0039-one-way-to-start-a-capture.md), so that a window added later is a second caller rather than a second capture. **It referenced SecureAD.Derivation and not SecureAD.Judgement until 2026-09-02**, on the reasoning that "judging here has nobody to offer the findings to" — which was wrong twice over: findings go into a store beside the evidence rather than to a person, and the owner had already said the command line must finish the judging so a run can complete overnight. It judges with `RuleCatalogue.All` and never a subset, per [`0082`](../decisions/0082-the-rule-catalogue-is-not-customer-tunable.md), so there is one definition of what an audit is. It exports no public types — its surface is its options and exit codes — which is why it sits outside the assemblies the architecture gates reflect over, held there by `CommandLineSurfaceGateTests` |
| SecureAD.Shell | 7 | SecureAD.Kernel, SecureAD.Evidence, SecureAD.Derivation, SecureAD.Judgement, SecureAD.Audit | The window. It is the second caller [`0039`](../decisions/0039-one-way-to-start-a-capture.md) anticipated rather than a second way to capture: `CaptureLauncher` constructs a `CaptureSession` exactly as the command line does, `DerivationLauncher` drives `Stage2aRun` and `JudgingLauncher` drives `JudgingRun` the same way. It references both stores and neither reaches across them: deriving writes `derivation.db` and judging writes its own file, and the window calls them in that order because derived facts are an input to judging rather than a product of it. WPF rather than WinUI 3 per [`0046`](../decisions/0046-the-shell-is-wpf.md), and built before the judgement half per [`0045`](../decisions/0045-the-shell-is-built-before-the-judgement-half.md). Its own internal layering is held by `ShellMvvmGateTests`: a view model names neither a screen type nor the disk, code-behind does nothing but `InitializeComponent`, and only `App.xaml.cs` constructs a concrete service. It sits on its own layer because two projects sharing one may reference each other without the downward rule noticing |

<!-- DEPENDENCIES:END -->

**The rule: a project may only reference a project in a lower layer.** Never sideways, never upward.

### Why this is a rule and not a preference

The direction above is correct today and is held up by nothing except three lines in three project
files. Adding one reference the wrong way would compile, pass every test, and go unnoticed.

What it would cost is not tidiness. The kernel is the part with no opinions about this product — it
knows what a security descriptor is, not what a bundle is or how a run works. That is what lets its
answers be tested without a database and reused without dragging anything behind them. A kernel that
referenced the bundle would stop being that, and the loss is invisible at the moment it happens and
irreversible by the time anyone minds: the previous product's domain project targeted Windows for no
reason its own contents needed, and presentation-shaped types moved in through the gap over years.
Nobody decided that either.

This was stated before the higher layers existed because it is a decision that gets more expensive
every week it waits. It now constrains seven production projects and every reference among them.

### What the rule does not do

It cannot tell you a dependency is *sensible* — only that it points downward. Capture may reference
the bundle, and whether a particular capture component *should* is a judgement for whoever writes it.
And it sees only project references: a dependency expressed through a shared file, a database table
or a configuration convention is out of its reach, which is the same limit the concept registry
records about itself.

### The downward rule is active

The rule now governs seven production projects. Several wrong-way references would not be circular:
for example, Evidence could otherwise acquire a dependency on Derivation, or Audit on Judgement.
Those references would compile while reversing the ownership of permanent observations and
disposable conclusions. `EveryProjectReferencePointsDownward` prevents that architecture from
changing merely because a convenient project reference was added.

### The gate was mutation-tested

| # | Mutation | Expected | Observed |
|---|---|---|---|
| 1 | The kernel made to reference the bundle | The direction rule fires | **Compiler refused it** — a circular reference. See above; the mutation was reverted and the rule re-tested from the document side |
| 2 | Layer numbers inverted, so every real reference points upward | The direction rule fires | `EveryProjectReferencePointsDownward` fired |
| 3 | A real reference removed from a `May reference` cell | The permission rule fires | `EveryProjectReferenceIsOneTheDocumentPermits` fired |
| 4 | A duplicate layer, and a row for a project that does not exist | Both bookkeeping rules fire | `NoTwoProjectsShareALayer` and `TheDocumentDescribesNoProjectThatDoesNotExist` fired, and the direction rule fired with them |
| 5 | The table's `BEGIN` marker renamed | The parse refuses rather than reading nothing | All seven checks fired, including the scanner self-test |

Every mutation was confirmed to have reached the file before the result was believed, and every one
was reverted.

## Where the seams are

A **seam** is a place two parts meet and neither can see inside the other. They are the joints the
product can be taken apart at, and they are worth naming because they are what makes the rest
replaceable.

- **The bundle** is the seam between capture and everything else. Per
  `0009` it is the reason the
  rebuild can proceed in stages at all. Per
  [`0013`](../decisions/0013-the-bundle-is-no-longer-a-two-way-contract.md) it is no longer shared
  with the old product, so its schema is free.
- **The directory** is the seam between the product and a customer's forest, and it is crossed in
  exactly one direction, by exactly one project, in exactly one stage.

  Two things about it were settled on 2026-08-11, with inventory rows B4 and B7, and both are held by
  build guards rather than by convention. **The unit of reading is one naming context, never one
  domain** — a search based at a domain root is offered referrals to four other partitions on the
  way past, and a paged search that follows them ends after one page reporting success. And **only
  one request is ever in flight against a controller**, which since the removal of the per-controller
  rate limiter is the only thing bounding the load a capture places on a customer's production
  server. Both are documented at `S-9` and
  `S-10`.

  The seam has a second half, and it now exists.
  [`IDirectoryChannel`](../../next/src/SecureAD.Audit/Capture/IDirectoryChannel.cs) is the one way
  the product speaks to a controller — send a request, get an answer —
  [`PartitionCapture`](../../next/src/SecureAD.Audit/Capture/PartitionCapture.cs) is the loop that
  reads one partition through it, documented at `S-12`, and
  [`LdapDirectoryChannelFactory`](../../next/src/SecureAD.Audit/Connect/LdapDirectoryChannelFactory.cs)
  is what puts a real domain controller on the other end, documented at
  `how a connection is opened`. The seam was written
  from the loop's side against a controller model and held unchanged when something real met it,
  which that document records member by member rather than asserting.

  A third thing about the seam was settled on 2026-08-12, and it is a decision about a customer's
  network rather than about this product's code. **Connection security is an ordered ladder of named
  rungs**, walked from the top until one answers, and its bottom rung — an unprotected connection —
  is reached only where the auditor declared before the run started that this run may use one. It is
  a declared allowance and never a fallback, and it is never remembered between runs. Recorded at
  [`0018`](../decisions/0018-connection-security-is-an-ordered-ladder.md) and held by
  `ConnectionSecurityGateTests`, which fails the build if anything but that one file opens a
  connection or decides a security level.

  **What was missing was not a component but a run, and it is no longer missing.** `CaptureSession`
  is the capture entry point decision `0039` requires, and both current hosts reach it. The target
  composition and deletion of duplicate host sequencing are fixed in [`WORKFLOW.md`](WORKFLOW.md).

  One thing about the seam is worth naming here because it is a property of the whole product rather
  than of one component. **Capture never asks for a SACL.** The audit half of a security descriptor
  is privileged, so requesting it would mean a customer had to grant this tool a privilege on every
  domain controller before it would read anything. The request asks for owner, group and DACL, and
  the value is bound by a test.
- **The sidecar** is the seam between a customer's annotations — notes, suppressions, declared scope
  — and the evidence. Per [`0015`](../decisions/0015-a-bundle-names-a-pattern-it-never-explains-one-away.md)
  and `0017` a customer's opinion never
  edits, filters or reduces the evidence; it sits beside it. That is what stops a clean report being
  produced by ticking a box.

## What holds this together

Four build-failure gates, each a way this codebase went wrong more than once. They are described in
[`README.md`](README.md) § Gates and documented at `S-5` and
`S-6`. The dependency rule above is enforced by
`ArchitectureDocumentationTests` in the same spirit but is not one of the six gates: those came from
the map's findings about the old product, and this one comes from the shape of the new one.

Two further guards arrived with capture, and neither is a general rule — each holds one specific
thing that is invisible at the moment it is lost. `DirectorySearchGateTests` allows a search request
to be built in one file and forbids any referral option other than `None` anywhere.
`SerializedDirectoryAccessGateTests` forbids the shapes that fan work out inside the capture
project. A third arrived with the connection: `ConnectionSecurityGateTests` allows one file to open
a connection or set a transport-security option, forbids any authentication type but Negotiate
anywhere, and holds the ladder's rung list to the levels the product reports. All three are gate 1's
shape rather than gate 1 itself: a correct mechanism, with a boundary obliging its use.

## What this document cannot tell you

Whether the shape is a good shape. It records what was decided and keeps the record honest against
the code; it does not argue that seven stages is the right number or that the layering is well
chosen. Those need a reader.
