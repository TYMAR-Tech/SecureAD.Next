# S-13 — Connect and discover, and what a customer's credentials cross

**Type:** slice
**Ledger rows:** A1–A10
**Size:** 10 ledger rows decided, 1 decision record, 2 new documents, 1 new guard, 1 component built
**Date:** 2026-08-12

---

## What this session was for

The rebuild could read a partition and could not read a forest, because nothing opened a connection.
[`IDirectoryChannel`](../../next/src/SecureAD.Audit/Capture/IDirectoryChannel.cs) had no
implementation, and `CaptureSearchRequestFactory.ApplyReferralPolicy` had no caller — which meant the
one setting the whole capture stage rests on was written down, guarded, and applied to nothing.

Branch A is where that is answered, and it is the branch at which a customer's credentials and a
customer's evidence cross a network. Nothing downstream touches a directory: per
[`0008`](../decisions/0008-live-verification-is-removed.md) capture is the only stage that does, and
per [`0009`](../decisions/0009-greenfield-in-place-with-the-bundle-as-seam.md) everything the product
ever says comes out of the one bundle capture produced. So a wrong answer here is not a bug that
shows up later. It is a promise the product cannot keep, made once, with nothing afterwards that
could notice.

## The question the owner answered

**How this product connects to a domain controller**, settled on 2026-08-12 and recorded as
[`0018`](../decisions/0018-connection-security-is-an-ordered-ladder.md). Connection security is an
ordered ladder of named rungs — LDAPS, then signed and sealed over Negotiate, then signed, then
unprotected — walked from the top until one answers. The bottom rung is reached only where the
auditor declared before the run started that this run may use one; it is a declared allowance and
never a fallback, it is stated per run and never remembered, and declaring it produces a finding
rather than silence. Simple binds are not on the ladder at all.

Everything below either follows from that or was decided because that answer made it necessary.

<!-- DISPOSITIONS:BEGIN -->

| Component | Disposition | Lands in |
|---|---|---|
| A1 | Rebuild | `SecureAD.Audit` |
| A2 | Rebuild | `SecureAD.Audit` |
| A3 | Rebuild | `SecureAD.Audit` |
| A4 | Rebuild | `SecureAD.Audit` |
| A5 | Rebuild | `SecureAD.Audit` |
| A6 | Delete | n/a |
| A7 | Rebuild | `SecureAD.Audit` |
| A8 | Rebuild | `SecureAD.Audit` |
| A9 | Defer | `SecureAD.Audit` |
| A10 | Defer | `SecureAD.App` |

<!-- DISPOSITIONS:END -->

## The decisions, and what each costs

#### A1 — Connection settings and authentication: Rebuild, and it comes across much smaller

Eighteen knobs became four values, and the shrinkage is the decision rather than a side effect.

With the ladder settled at [`0018`](../decisions/0018-connection-security-is-an-ordered-ladder.md),
most of what the previous component held is no longer a choice. There is no LDAPS preference,
because the ladder tries LDAPS first on every connection. There is no signing requirement, because
signing is not required, it is *preferred*, and what happens when a controller declines is decided by
the ladder and not by a setting. There is no protocol version, because there is one. There is no
authentication mode, because there is one.

**A setting an operator could use to pin the transport would be a way to reach the bottom rung
without declaring anything**, which is the whole thing the decision forbids, arrived at by a
different door. So the transport is not configurable and that is deliberate.

What survives is [`DirectoryConnectionSettings`](../../next/src/SecureAD.Audit/Connect/DirectoryConnectionSettings.cs):
who the run binds as, what it declared about unprotected connections, and how long one attempt at one
rung may take. Every one of them is read by something. That is the same test ledger row B1 applies on
the capture side, where five of eighteen settings had no consumer and were shipped, validated,
edited and written into the bundle anyway.

**What happens to a customer's credentials** is the other half of this row, and the answer is that as
little as possible happens to them. Two cases, no third: the account the product already runs under,
or an account typed in for this run. Nothing is persisted, nothing is logged, and the password is not
on the type's public surface — `DirectoryCredential` is deliberately not a record, because a record's
compiler-generated `ToString` prints every member it has, and printing the object holding a secret is
how a secret normally escapes. The account name is withheld too, which is slightly stronger than
strictly necessary and is taken on purpose: a user name is not a secret but it is half of one, and an
audit tool's logs go into support tickets.

**The `SavedCredential.cs` question was answered by looking.** The map records a file of that name
containing no such type, and the reason is that a credential-persistence feature was designed and
then not built. That was right and it stays right. A tool that reads a directory, writes nothing to
it, and holds no secrets has no business keeping a customer's administrative password from one week
to the next. Naming §6 of the map's rename — the file becomes `AuthenticationMode.cs` — is moot,
because there is no authentication mode.

#### A2 — The connection: Rebuild, and built this session

The whole of [`S-14`](../next/S-14-the-connection.md). Ledger row A2 is now Done.

The map records this component as *"the single choke point for all LDAP connections… Nothing else
constructs a connection"*, and that judgement is kept and made enforceable rather than trusted:
`ConnectionSecurityGateTests` fails the build if a connection is opened, or a transport-security
option assigned, anywhere but the one file. The map's Naming §2 rename is taken — it is a factory,
not a manager, and the interface was always the one telling the truth — and the doc comment claiming
connection pooling goes, because it was describing a design that never landed and it invited callers
to assume connections were cheap.

**The seam survived contact.** [`S-12`](../next/S-12-the-capture-passes.md) wrote `IDirectoryChannel` from
the loop's side against a controller model, and this row is the first thing to meet it from the
other. It held unchanged: every member maps onto something a live connection actually has, which is
recorded in S-14 as a table rather than asserted. One thing was added — the RootDSE answer also
carries `namingContexts`, which arrives in the same round trip and is what A8 needs — and the request
for it is built by `CaptureSearchRequestFactory`, because the one-place rule applies to a request
nobody had needed yet.

#### A3 — Name resolution: Rebuild, and the global-catalog half does not come across

Turning a domain name into a list of domain controllers stays. It is unavoidable and the map records
the thing worth keeping about it, which is that the result is cached because the underlying call
costs twenty to forty-five seconds — *"the cache is load-bearing rather than an optimisation"*.

The global-catalog half goes. A global catalog holds a partial replica of every domain, and this
product does not want a partial anything: per [`S-9`](../next/S-9-the-capture-unit.md) the unit of reading is
one naming context read whole from a controller that serves it, so a global catalog is the wrong
shape of answer to a question capture never asks.

The map's Naming §1 rename is taken. `DnsSrvResolver` named the fallback rather than the mechanism —
its own summary says it uses the locator API with DNS SRV as a fallback — and propagated that into
every caller through a type called `DcSrvRecord` holding results that are not SRV records. Anyone
debugging a resolution failure started at DNS because the type told them to.

#### A4 — Choosing a controller: Rebuild, and one of its two filters is wrong for this product

Determinism is the thing to keep, and the map says why: it is what makes a capture reproducible.
Same-site preference then a stable ordering is right and comes across.

The capability filter does not. It required a candidate to be `Reachable | Writable`, and this
product never writes to a directory — per [`0008`](../decisions/0008-live-verification-is-removed.md)
it does not even verify against one. Requiring a writable controller excludes read-only domain
controllers for no reason this product's behaviour supports, and a branch office whose only local
controller is read-only is exactly the site where reading remotely costs the most.

**What replaces `Writable` is `ServesThisPartition`**, which is a question about the actual work
rather than a proxy for it, and `CaptureUnit.ConfirmServedBy` already answers it.

#### A5 — Probing candidates: Rebuild

The I/O half of A4: resolve the candidates, ask each one what it can do, hand the choice to the
policy. It comes across with the ladder underneath it, which changes what a probe finds out — a
candidate that answers on no rung this run may use is not a candidate — and with the map's Naming §4
rename, because `DcDiscoveryService` and `ForestDiscoveryService` were two altitudes of the same word
and `DcEnumerator` versus `ForestDiscoveryService` explains itself.

#### A6 — Routing and failover: Delete

This is the row that changed most, and it is deleted rather than rebuilt because the thing it does
has been decided against elsewhere.

The component is a session-wide answer to *"which controller do I use for domain X right now"*, with
failover when one stops answering. Three things already settled make it wrong here:

- **A unit names its controller before the run starts** — [`S-9`](../next/S-9-the-capture-unit.md) — so that
  under fail-fast a failure names one unit unambiguously. A routing table that could answer
  differently at hour two would break exactly that.
- **The failure policy already decided what happens when a controller stops answering** —
  [`S-10`](../next/S-10-politeness.md) — and the answer is three attempts, one restart of the naming context
  on a fresh connection to the *same* controller, and otherwise stop. Moving to a different
  controller was named as the decision point and deliberately not built, because no capture of the
  predecessor has ever failed in production — F-S7-35 — so it is machinery for an unobserved event.
- **A capture is not a frozen instant**, but it is not arbitrary either. Half a partition from one
  controller and half from another is two views of a replicating directory stitched together with
  nothing recording the seam, and the product would have no way to say which objects came from
  where.

What the map identified as this component's real value — that re-discovery happens only when every
known controller for a domain has failed, never on a timer — is a property of a component that no
longer exists. The negative cache and the per-domain lock go with it.

**What is not lost:** the per-domain list of candidates. That is A3 and A5, and it is what a future
row would need if failover is ever reinstated. Deleting the router does not delete the knowledge of
which controllers exist.

#### A7 — Forest topology: Rebuild, and it is the row capture is actually waiting for

[`S-12`](../next/S-12-the-capture-passes.md) is explicit about the gap this fills. `CapturePlan` is built
from a list of partitions it is *handed*, and working out which is which is branch A's, because a
partition list alone cannot tell a domain from an application partition —
`DC=DomainDnsZones,DC=example,DC=com` is spelled exactly as a domain is, and the only reliable answer
is in the configuration partition's cross-references. A component that guessed from the name would be
right on every forest anybody builds to test it and wrong at a customer.

So this row owns the cross-reference read. The map's note that its outputs are deterministic matters
beyond this branch, because it is the denominator coverage is later measured against.

Trust classification comes across; global-catalog enumeration does not, per A3.

**Fire-and-forget seeding does not come across.** The map's Would-do-differently §4 records the call
made without awaiting, so that a failed seed still reported success and every later cross-domain
operation quietly paid the penalty the seed existed to avoid. There is no router to seed now, and
where a similar hand-off appears it is awaited: a performance guarantee that fails silently is
indistinguishable from one that was never made.

#### A8 — Preflight: Rebuild, and it keeps its job because the job got bigger

The map records preflight as one of the previous product's good decisions and says it should be
extended rather than dropped: *"Validating DC reachability before committing to a multi-hour capture
is cheap… and prevents the worst failure mode this tool has."* That is right, and B4 and B6 between
them have already taken the cheapest part of it — `CapturePlan` confirms every unit against the
partition list a controller published.

What is left is everything that needs a live connection, and there is now more of it than there was:

- **Can we connect at all, and on which rung.** The ladder is walked here, once per controller,
  before hours of capture are committed. A run that would have to declare an allowance and did not
  finds out in its first minute.
- **Are the credentials good.** The bind is the check; there is nothing else to write.
- **Does this controller serve this partition,** asked of the live RootDSE rather than of a list
  somebody handed over — which is the same question `ConfirmServedBy` answers and the reason that
  method exists.
- **Is there room for the bundle** — as a *floor*, and deliberately not as an estimate. A run
  refuses to start below an obviously-too-small amount of free space, which is a bound needing no
  model, and it reports what it found so an operator who did not know their disk was filling now
  does. It makes no claim about whether the space is enough, because nothing could: a bundle's size
  is dominated by how many access control entries hang off an object rather than by the object
  count. **What stops a truncated bundle being read as a whole one is the seal, not this check** —
  per [`0003`](../decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md) an incomplete capture
  is refused. Watching the space fall during a capture, and stopping deliberately rather than being
  killed mid-write, is ledger row C13's and is the half with the value in it.

**The concurrency tension is real and it is resolved rather than filed.** The previous preflight was
bounded at four-way concurrency, and `SerializedDirectoryAccessGateTests` forbids a file that talks
to a directory from fanning work out. The guard is not being widened, and the answer is not to split
the file in two to satisfy the letter of it: **preflight is sequential.** N controllers at ten
seconds each is a minute or two at the size of forest this product operates on, against a capture
measured in hours, and the previous fan-out was buying a saving nobody would notice at a cost the
guard exists to prevent.

That is a straight trade and it is worth naming as one: this is slower than it was, on purpose.

#### A9 — Session composition root: Defer, and gate 5b does not unblock here

**This branch does not produce something that runs**, and saying so plainly is the point, because
gate 5b has now been forecast wrongly twice — at B6, and before that at K16.

Ledger row A2 is a library. It opens a connection when something calls it, and nothing does: there is
no `Main`, no window, and no run driver. Composing a session is only meaningful once there is
something to compose *for*, and what a run needs — a plan, a store to write into, a place to report
progress — is branch B and branch C, neither of which is built. Building a composition root now would
be composing a run that does not exist, and it would be the third component in a row to be forecast
as the thing that finally runs.

So the trigger does not move. It stays on **B20**, where F-S7-42 already put it, and A9 is deferred
with B20 named as the row it waits for rather than left open-ended. See F-S13-3.

**The map's Would-do-differently §5 is answered rather than inherited.** There is still no
dependency-injection container. What changes is the consequence the map identified: the previous
composition root handed out nullable services that every caller guarded at each use. Gate 1's second
half already forbids that shape in the rebuild — no service constructor parameter may default to
`null` — so a session object here will hand out services that cannot be absent, or it will not
compile.

#### A10 — Discovery UI: Defer

There is no window. `SecureAD.App` is phase 3 and does not exist, and a screen deferred for that
reason is not a decision anybody needs to revisit until it does.

One thing about it is decided now rather than then, because it is cheap now and expensive later: **the
declaration of an unprotected allowance is not a checkbox that persists.** Whatever this screen turns
out to be, it states the allowance for one run and forgets it, and it does not offer a way to pin the
transport. Both follow from [`0018`](../decisions/0018-connection-security-is-an-ordered-ladder.md)
and both are the kind of thing a UI quietly reintroduces if nobody wrote it down.

## Findings

### F-S13-1 — A run that read a forest over an unprotected connection has nowhere to say so

- **Severity:** correctness-risk
- **Confidence:** verified, by construction
- **Evidence:** [`ConnectionSecurityLog`](../../next/src/SecureAD.Audit/Connect/ConnectionSecurityLog.cs)
  records the rung each controller answered on, and `AnyUnprotected` is the question a report has to
  ask. Nothing reads it, because there is no report: branch I is phase 3 and not started.
- **What happens to a user:** a report that looks exactly like one produced over LDAPS. Evidence
  gathered over a channel that could have been altered in transit is not the same evidence — an
  attacker able to alter LDAP responses can remove the entry naming their own foothold, and the
  report then says nothing is wrong. Per
  [`0002`](../decisions/0002-absent-view-means-degraded-run.md) that difference is never rendered
  away, and this is the case where rendering it away would be worst.
- **Why it is this way:** the level can only be recorded where the connection is opened, and it can
  only be disclosed where a report is written. Those are different branches and different phases.
- **How it was acted on:** registered against ledger row **I3** — degraded-output presentation —
  which is where a run that is not a clean run is presented as one. Not left in this document,
  because a caveat that lives only in a slice is a caveat nobody reads at the moment it matters,
  which is the failure [`0016`](../decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md)
  records.
- **Test cover:** `OwedFindingHomeTests` holds the obligation to the row in both directions.
- **Status:** **OPEN**, owed by I3.

### F-S13-2 — A controller that refuses a protected connection is a finding about the forest, and there is no finding pipeline to put it in

- **Severity:** correctness-risk
- **Confidence:** verified, by construction
- **Evidence:** `ConnectionSecurityLog.RefusedIntegrity` names every controller that would accept
  neither signing nor TLS. Nothing turns it into a finding, because branch E is not started.
- **What happens to a user:** they are not told something the product found out about their forest.
  Microsoft's hardening guidance treats unsigned LDAP as something to eliminate, and Windows Server
  2025 requires LDAP signing by default on new deployments while Windows Server 2019 and earlier
  accepts both signed and unsigned binds ([LDAP signing for Active Directory Domain
  Services](https://learn.microsoft.com/windows-server/identity/ad-ds/ldap-signing)). A forest with a
  mix of both has a real weakness on the older controllers, this product is standing right there when
  it happens, and saying nothing wastes it.
- **Why it is this way:** the observation is made where a connection is opened and the finding is made
  where the rule catalogue runs.
- **How it was acted on:** registered against ledger row **E1** — the findings pipeline phase. It also
  keeps the allowance honest, which is the reason it is not optional: ticking the box produces a
  finding rather than nothing, so the easy path is not the quiet one.
- **Test cover:** `OwedFindingHomeTests`.
- **Status:** **OPEN**, owed by E1.

### F-S13-3 — Branch A does not unblock gate 5b either, and this is the third row that was expected to

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** gate 5b asks what a *running* consumer reaches. It was forecast to unblock at K16,
  then at B6 — F-S7-42 — and branch A was the next candidate, because opening a connection sounds
  like the thing that finally runs. It is not: ledger row A2 is a library with no `Main` and no
  caller, and A9, the row that would compose a session, is deferred because there is nothing to
  compose for until there is a run driver and a store.
- **What happens to a user:** nothing directly. What it costs is the gate. Each time the forecast
  moves without being re-derived, gate 5a's bookkeeping looks like it is being kept honest by a
  deadline that is not real.
- **Why it is this way:** three consecutive rows each looked like the last thing standing between the
  rebuild and something that runs, and each was a library. The pattern is worth naming: a component
  that talks to the outside world is not the same as a component that starts.
- **How it was acted on:** the trigger stays on **B20**, where F-S7-42 put it, and A9 now names B20 as
  the row it is deferred behind rather than being deferred open-ended. The three things still missing
  before anything runs are stated rather than implied: a run driver (B20), somewhere to write what is
  read (branch C), and an entry point (A9 or J1).
- **Test cover:** `SurfaceRegisterTests`, whose decay check fails the build if a register entry
  outlives the row it waits for.
- **Status:** **OPEN**, owed by B20.

### F-S13-4 — Gate 4 caught a connection log that could not tell "nothing was wrong" from "nothing was reached"

- **Severity:** correctness-risk
- **Confidence:** verified, by observing it
- **Evidence:** the first version of `ConnectionSecurityLog` exposed the controllers that answered and
  the ones that refused integrity, and nothing else. `UnvouchedResultGateTests` failed the build on
  both members. A run in which every connection failed and a run in which every connection was
  protected produce the identical empty `RefusedIntegrity`.
- **What happens to a user:** a report saying every domain controller accepted a protected connection,
  produced by a run that reached none of them. That is
  [`0002`](../decisions/0002-absent-view-means-degraded-run.md)'s exact prohibition, reached in the
  one place where it would be most convincing.
- **Why it is this way:** the type was written from the successful path, where a failure to connect
  ends the run and therefore never reaches the log. That is true today and stops being true at A8,
  which asks every controller the question at once and must report all the answers rather than the
  first.
- **How it was acted on:** the log carries `Errors`, and the ladder walk records a failure there as
  well as returning it. The gate was not exempted, and the exemption it did take —
  `ConnectionSecurityLadder`, a four-row table compiled into the assembly that reads nothing and
  cannot fail — is the third entry on an allowlist whose two decay tests cover every entry.
- **Test cover:** `ARunThatReachedNoControllerIsNotARunThatFoundNothingWrong`.
- **Status:** **CLOSED**, 2026-08-12, by ledger row A2.

### F-S13-5 — Four scratch files from a previous session were left in `docs/next/` and were failing the build

- **Severity:** maintainability
- **Confidence:** verified, by observing it
- **Evidence:** `RebuildStatusDocumentationTests.EverySliceTheStatusNamesExists` failed on a file
  named `S-7-B6-section.tmp.md`. `git status` showed four untracked `.tmp.md` files in `docs/next/`,
  left by the session that built B6 — which used them correctly, to avoid multi-line here-strings,
  and did not delete them afterwards.
- **What happens to a user:** nothing. What it produces is a test suite that is red on arrival for a
  reason unrelated to the work in hand, which is the condition under which a real failure gets
  waved past as "that one's always broken".
- **Why it is this way:** the session rule says to write long text to a file rather than use a
  here-string, and to check the file is gone afterwards. The first half was followed and the second
  was not, and nothing checked.
- **How it was acted on:** the four files were deleted. The rule already exists and does not need
  restating; what is worth carrying is that the check is cheap — `git status --porcelain docs/` at
  the end of a session shows it immediately.
- **Test cover:** `RebuildStatusDocumentationTests` already fails on a stray `S-*.md`, which is how
  this was found. It does not catch a stray file with another prefix.
- **Status:** **CLOSED as practice**, 2026-08-12, by ledger row A2.

### F-S13-6 — The check that every row is explained was measuring the whole document for the last row

- **Severity:** correctness-risk, in the checking rather than the product
- **Confidence:** verified, by observing it
- **Evidence:** `ConnectDispositionDocumentationTests.EveryRowIsExplainedAndNotMerelyListed` asserts
  a floor on how much text sits under each row's heading. Its section scan ran from a row's heading
  to the next `####` heading — and A10 is the last row, so its section ran on through the findings
  to the end of the file. A10's reasoning was reduced to the single word *"Deferred."* and the check
  passed.
- **What happens to a user:** nothing directly. What it produces is a check that appears to hold ten
  rows to a standard and holds nine, with the tenth — always the last one written, and therefore
  always the one written in a hurry — free to be a heading and a shrug. That is the same shape as
  gate 5's original wording, the S-2 document guard, and F-S7-43: a check that passes while
  measuring nothing.
- **Why it is this way:** a section boundary defined by "the next thing like me" has no answer for
  the last one. It is invisible on reading, because the code says exactly what it means to say.
- **How it was acted on:** the scan stops at any following heading rather than only at the next
  row's, and the self-test now measures the **last** section specifically and asserts it does not
  contain the first finding's identifier. It was found by mutating in the direction the check is
  supposed to fire, which is the argument for mutating both directions rather than only confirming
  a guard passes on clean code.
- **Test cover:** `TheCheckReadsBothTheTableAndTheLedgerAndDoesNotMatchEverything`, which now fails
  if the last row's section runs past its own heading.
- **Status:** **CLOSED**, 2026-08-12, by ledger row A2.

## What this session did not settle

**Nothing about a real domain controller.** No bind was performed, no TLS handshake completed, and no
controller declined anything. The ladder's descent is tested and the connection itself is not, which
S-14 states rather than glosses. That joins the three observations ledger row B20 already owes to a
lab session.

**Channel binding** is named in S-14 and not built. It is a property of a TLS session, so it applies
only to the top rung, and Windows Server 2025 sets it to "when supported" rather than requiring it.
No run has yet met a controller that required it, and building a defence against an unobserved
refusal is the same shape of mistake as the failover dialog F-S7-35 refused.

**Which controller serves which partition in a multi-domain forest** is A7's, and A7 is decided and
not built. Until it is, `CapturePlan` still has to be handed its partitions.
