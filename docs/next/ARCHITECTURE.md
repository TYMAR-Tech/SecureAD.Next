# Architecture

How the rebuilt product is put together: the stages a run passes through, the projects those stages
live in, and which project is allowed to use which.

**This document is written as the product is built, not afterwards.** Each stage below gains its
detail when the inventory rows behind it land. A stage that says *not built* says so; it is not a gap
someone forgot to fill. Writing it at the end would mean writing it from memory at the moment memory
is worst, and the previous product's architecture document is the evidence — it was true when
written and describes six things that are no longer so.

`ArchitectureDocumentationTests` binds it: this document must name every project that exists and no
project that does not, and the dependency rule below is enforced against the project files rather
than trusted.

## What a run is

One run produces one **bundle** — a single file that is the complete evidence of a forest as it
stood at one moment. Everything the product ever says is said from a bundle, and nothing is said
from a live directory: per [`0008`](../decisions/0008-live-verification-is-removed.md) the only
component that touches a domain controller is capture.

That is the shape of the whole product, and it is worth stating plainly because it is unusual and it
is load-bearing. A screen showing a permission is not asking the directory. It is reading a file. So
a finding can be reproduced a year later, on a machine that has never seen the forest, and will say
the same thing — which is what makes it evidence rather than an opinion.

| # | Stage | What happens | Branch | State |
|---|---|---|---|---|
| 1 | **Connect and discover** | Find the forest's domains, choose a domain controller for each unit, and check before starting that each one can serve what it will be asked for | A | Building. All ten rows decided, A1 and A2 done: a connection can now be opened, over the most protected transport a controller will accept. What is missing is discovery — nothing yet works out which partitions a forest has |
| 2 | **Capture** | Read every naming context in the forest — objects, their permissions, group memberships — plus the schema and extended-rights containers once per forest | B | Building. B2, B4, B6, B7 and B8 done: a single partition can now be read whole, and with A2 it can be read over a real connection. What is missing is a run — nothing drives the loop, which is B20 |
| 3 | **Store** | Write what capture read into the bundle, and seal it | C | Building. The write half is decided and built: C1, C3, C10, C11 and C15, plus capture's two writers B9 and B10. A bundle can now be created, written to, sealed and refused. What is missing is a caller — nothing joins the partition capture can read to the bundle that can store it, which is B20 |
| 4 | **Derive and analyse** | Build the control graph — who can take over what, and by which step — from the permissions captured | D | Not built |
| 5 | **Rules and findings** | Apply the rule catalogue to the derived graph and record what it finds, with the evidence behind each | E | Not built |
| 6 | **Read back** | Grids, dashboards and reports, all reading the bundle | I, J | Not built |
| 7 | **Compare** | Two bundles, and what changed between them | G | Not built |

Stage 2 is the one that cannot be redone. A forest is only readable as it is today, so anything
capture does not collect is not a defect to fix in the next release — it is a forest that has to be
captured again. That is why capture's decisions get the scrutiny they do, and why
[`S-8`](../layers/audit/the-attribute-catalogue.md) exists.

## The projects, and which may use which

`SecureAD.App`, the window a user sees, is phase 3 and does not exist yet. It appears below with no
row of its own for the same reason nothing else absent does.

<!-- DEPENDENCIES:BEGIN -->

| Project | Layer | May reference | Owns |
|---|---|---|---|
| SecureAD.Kernel | 1 | - | What is true about Active Directory regardless of this product: security descriptors, permission canonicalisation, distinguished names, schema identifiers, and the single answer to whether a right is dangerous. Plus the two contracts everything else must adopt, `Result` and `AuditError` |
| SecureAD.Evidence | 2 | SecureAD.Kernel | The bundle: its schema, and reading and writing it |
| SecureAD.Audit | 3 | SecureAD.Kernel, SecureAD.Evidence | Capture, derived analysis, and the rule catalogue. The only project permitted to open a connection to a directory |
| SecureAD.Cli | 4 | SecureAD.Kernel, SecureAD.Evidence, SecureAD.Audit | The command that starts a capture, and nothing else. It reads a command line and calls `CaptureSession`; every decision a run makes is made below it, per [`0039`](../decisions/0039-one-way-to-start-a-capture.md), so that a window added later is a second caller rather than a second capture. It exports no public types — its surface is three options and four exit codes — which is why it sits outside the assemblies the architecture gates reflect over, held there by `CommandLineSurfaceGateTests` |
| SecureAD.Shell | 5 | SecureAD.Kernel, SecureAD.Evidence, SecureAD.Audit | The window. It is the second caller [`0039`](../decisions/0039-one-way-to-start-a-capture.md) anticipated rather than a second way to capture: `CaptureLauncher` constructs a `CaptureSession` exactly as the command line does. WPF rather than WinUI 3 per [`0046`](../decisions/0046-the-shell-is-wpf.md), and built before the judgement half per [`0045`](../decisions/0045-the-shell-is-built-before-the-judgement-half.md). Its own internal layering is held by `ShellMvvmGateTests`: a view model names neither a screen type nor the disk, code-behind does nothing but `InitializeComponent`, and only `App.xaml.cs` constructs a concrete service. It sits on its own layer because two projects sharing one may reference each other without the downward rule noticing |

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

This is stated **now**, at three projects and three connections, because it is a decision that gets
more expensive every week it waits. At three edges the rule is obvious and free. At thirty it is a
month of untangling, and by then something depends on the tangle.

### What the rule does not do

It cannot tell you a dependency is *sensible* — only that it points downward. Capture may reference
the bundle, and whether a particular capture component *should* is a judgement for whoever writes it.
And it sees only project references: a dependency expressed through a shared file, a database table
or a configuration convention is out of its reach, which is the same limit the concept registry
records about itself.

### The downward rule is not yet doing any work, and that is worth saying

With three projects and three connections, **every** upward reference is also a circular one — the
kernel cannot reference the bundle without the bundle already referencing it — so the compiler
refuses it before any test runs. That was found by trying it: adding the reference produced a build
failure, not a test failure.

So today the downward rule catches nothing the compiler does not already catch. It is not therefore
a check that measures nothing — the other five checks in `ArchitectureDocumentationTests` all fire
against real mutations, and they are the ones holding the document to the projects. But the
direction rule specifically is **prospective**, and it starts working the moment there is a fourth
project: a sideways reference between two projects on the same layer is not circular, and neither is
an upward one to a project that does not reference back. `SecureAD.App` is coming, which is when
that stops being hypothetical.

This is recorded rather than left implied, because a rule that appears to be guarding something and
is not is the failure this repository has committed three times.

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
  server. Both are documented at [`S-9`](../layers/audit/the-search-capture-issues.md) and
  [`S-10`](../layers/audit/limits-and-failures.md).

  The seam has a second half, and it now exists.
  [`IDirectoryChannel`](../../next/src/SecureAD.Audit/Capture/IDirectoryChannel.cs) is the one way
  the product speaks to a controller — send a request, get an answer —
  [`PartitionCapture`](../../next/src/SecureAD.Audit/Capture/PartitionCapture.cs) is the loop that
  reads one partition through it, documented at [`S-12`](../layers/audit/how-a-controller-is-read.md), and
  [`LdapDirectoryChannelFactory`](../../next/src/SecureAD.Audit/Connect/LdapDirectoryChannelFactory.cs)
  is what puts a real domain controller on the other end, documented at
  [`how a connection is opened`](../layers/connect/how-a-connection-is-opened.md). The seam was written
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
  is the composition root decision `0039` requires, `Program.cs` builds the channel factory directly,
  and the shell reaches a capture through `CaptureLauncher`. Whether gate 5b can now be turned on is
  P-84; it was deferred against an entry point that exists.

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
