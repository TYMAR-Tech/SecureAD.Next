# What preflight proves

**Layer.** The pass that asks every domain whether it can actually be read, before a run commits
hours to a controller that was never going to work — and the file it leaves behind.

The code is [`Preflight`](../../next/src/SecureAD.Audit/Connect/Preflight.cs),
[`PreflightDispatch`](../../next/src/SecureAD.Audit/Connect/PreflightDispatch.cs),
[`DomainPreflightRead`](../../next/src/SecureAD.Audit/Connect/DomainPreflightRead.cs),
[`PreflightReport`](../../next/src/SecureAD.Audit/Connect/PreflightReport.cs),
[`PreflightFile`](../../next/src/SecureAD.Audit/Connect/PreflightFile.cs),
[`NamedControllerCheck`](../../next/src/SecureAD.Audit/Connect/NamedControllerCheck.cs) and
[`CaptureSession`](../../next/src/SecureAD.Audit/Connect/CaptureSession.cs).

Governed by [`0048`](../decisions/0048-preflight-proves-a-controller-before-a-run-commits.md),
[`0039`](../decisions/0039-one-way-to-start-a-capture.md),
[`0055`](../decisions/0055-the-pdc-emulator-is-established-at-preflight.md) and
[`0063`](../decisions/0063-excluded-never-looks-like-unreachable.md).

---

## Why it exists

Capture is fail-fast and a forest is only readable as it stands today, so **discovering at hour two
that a child domain was never reachable costs the whole capture.** Preflight is that check on its
own, which is what makes it worth ten seconds before a run of several hours.

It catches everything that would otherwise end a multi-hour run: a controller that refuses every
rung of the connection ladder, a forest whose cross-references cannot be read, a domain whose DNS
name resolves to nothing, and a controller that does not serve the partition it was chosen for.

**It is the same check a run performs before reading, rather than a second one.** Two
implementations of *can this run work* would eventually disagree, and the first sign of it would be
a validate that passed and a run that did not.

---

## It never stops early, and that is the point of it

> **Every question is answered for every domain before any is allowed to stop the run.**

The loop this replaced returned on the first bad domain, so a forest of nine domains with three
faults cost **four validate passes to discover three facts that were all knowable in one** — each
pass repeating discovery and reconnecting to every healthy domain. And no screen could show a row
per domain, because nothing of that shape existed.

**A success does not mean the run may proceed.** It means every domain was asked and the answers are
in the report. Whether the run may proceed is `PreflightReport.RunMayProceed`, asked *of* the report.

**Two failures are still single and still stop everything**: finding the forest at all, and the
discovery that follows it. Neither can be reported per domain, because until the forest has described
itself there are no domains to report on — a per-domain shape there would be a table with nothing in
it and no reason given.

---

## Several domains at once, and no controller twice at once

Those are two different rules and only the first of them changed.

`0048` originally made the whole pass sequential. A forest of thirty domains at ten seconds each is
five minutes an operator spends watching a window before he may press anything, and it buys nothing
— **because the reason for the original rule was never the count of connections but the risk of two
requests meeting on one machine.**

That risk is now held by `PreflightDispatch`, which lets every controller be asked at once and each
one only once at a time.

**Turns are taken by host, not by domain.** Two domains pinned to one controller is not something
Active Directory produces, because a writable controller holds one domain — but `ControllerSelection`
has no rule against it and will pin the same host twice if handed a forest that declares one. **A
concurrency that is safe because the directory happens to be shaped a certain way is the defect this
exists to avoid**, so the safety is held in code instead.

**Nothing waits for a host while already holding one**, so there is no order in which two subjects
can wait on each other.

**Answers come back in the order the subjects were given**, not the order they arrived. A report
ordered by whichever controller answered first would put the same forest in a different order every
run, and an operator comparing two runs would be reading a difference the forest does not have.

**The `Task.Yield` is not tidiness.** Asking a subject begins by opening a connection, and that is
synchronous. Without it the first subject would run its whole connection ladder on the calling thread
before the second had started, and the pass would be **parallel in shape and sequential in fact** —
which is exactly the ten seconds per controller it is meant to overlap.

### Three files, because a file may dispatch or read, never both

`SerializedDirectoryAccessGateTests` holds this, and it is why `Preflight` and `DomainPreflightRead`
were split on 2026-08-16. Splitting them changed no behaviour; it made the rule enforceable on a file
that had never been watched, because the guard matched only raw LDAP type names and everything in the
reading half speaks through `IDirectoryChannel`.

| File | Does |
|---|---|
| `Preflight` | Keeps the connections and the plan; decides which domains are asked |
| `PreflightDispatch` | Fans work out over opaque subjects and host names; knows nothing of directories |
| `DomainPreflightRead` | Does the reading, strictly serially |

**The reading half writes nothing outside its own return value**, and it once did the opposite: the
loop carried `roles` and `selection` from one domain to the next and rewrote both mid-pass, so a
domain's re-pin re-ranked every other domain as a side effect. That was inert only because a
controller holds one domain in a real forest. **An assumption that holds by luck stops holding the
moment two of these run at once**, which is why the state is gone rather than guarded.

**The connections are closed again immediately.** A capture opens its own, per the failure policy, so
holding these open would save nothing and would keep a session on every controller in the forest for
the length of the run.

---

## What one domain is asked

1. **Can a connection be opened at all**, and on which rung.
2. **Does this controller serve the partition it was chosen for**, asked of its live RootDSE.
3. **Can the domain's Password Settings Container be read.**
4. **Which controller is this domain's PDC emulator** — one extra base request on a connection that
   already exists, per `0055`, which is why it costs no connection of its own.

The plan's configuration and schema units are not asked about. They were read from the bootstrap
controller and `CapturePlan` already confirmed them against that controller's own published partition
list. What it could not confirm is every *other* domain, because it holds one controller's list — a
check written there would pass for every other domain no matter what (`F-S28-2`). Here there is a
real connection to ask.

**A failure at any point stops that domain and never the pass.** What it does not do is invent
answers to the questions it did not reach: they stay `NotAsked`.

### A controller that was never reached has no rung, and cannot be given one

> `RungReached` is absent rather than carrying a worst-case value.

A ladder walk that was answered by nothing has observed nothing about the controller's security
posture. Reporting such a walk as though the controller had refused every protected rung is
`F-S35-1` — a security claim about a customer's forest that the product did not measure — **and the
nullable type is what makes repeating it impossible rather than discouraged.** The same reasoning
governs the ladder itself; see [`the connection ladder`](the-connection-ladder.md), including the one
place it is still got wrong.

### Three states, not a boolean

`PreflightAnswer` exists for one reason. A question preflight never got to ask, and a question asked
and answered *no*, **have opposite remedies** — the first is a network or naming fault, the second is
a fact about the customer's forest. `0002` forbids collapsing them, and a boolean has nowhere to put
the difference: `false` would have to mean both.

`No` on the Password Settings Container deliberately does not say *why*: Active Directory answers a
caller lacking list access with the same result code an absent container would produce.

**An unreadable Password Settings Container does not stop the run.** `0048` states that Enterprise
Admins is not required and that the supported posture is an ordinary account with read access
delegated per domain, so a run that refused to start over one container would refuse the posture that
record supports. What the answer buys is paid later and in the open: a report that says *it could not
tell*, instead of one saying the domain has no fine-grained password policy when it has several.

**A cancellation is not an answer and is not caught.** An operator who stopped the check has not
discovered anything about the container.

---

## What the report says, and what it refuses to say

| Asked of the report | Means |
|---|---|
| `IsComplete` | The pass did its own job — every declared domain has a row and every row was asked everything |
| `RunMayProceed` | Every domain the forest declared can be read |
| `Blocking` | The domains a capture could not read |
| `CouldNotReadPasswordSettings` | Answered, but the container was unreadable — does not block |
| `ReadFromPdcEmulator` | Being read from its own PDC emulator because nothing else was available — does not block |
| `ChosenWithoutFullKnowledge` | Ranked without every input — does not block |

**`IsComplete` and `RunMayProceed` are different questions**, and the case that matters is a report
with no rows at all: without the first, it would be indistinguishable from a forest in which every
domain answered, because both hand back an empty `Blocking`.

**`Refusal()` names every domain that failed rather than the first.** A caller returning a `Result`
needs one error to return, and building it from every blocking row is what stops the collected
answers being thrown away at the last moment — **the failure this whole pass exists to remove,
reappearing one layer up.**

**Nothing here is an exclusion.** A domain the run could not read and a domain an operator chose to
leave out are different events with opposite meanings, and `0063` requires that they never share a
representation. **There is no member an exclusion could be recorded in, and that is deliberate rather
than pending.**

---

## The file

`preflight.json` is written into the run's own directory before a single object is read. It closes
`F-S35-4`: the predecessor recorded which controller actually answered and the rebuild recorded
nothing, so a bundle could not say which controller served each domain — which `0040` says it should.

**It has a shape of its own rather than the report serialized directly**, because what a run wrote
down must not change every time an in-memory type gains a member. The names in it are the file's
contract with whoever reads it.

**`AllQuestionsWereAsked`, not `IsComplete`.** It sits beside `SelectionWasInformed`, which is a
different question, and the two are routinely true and false together. A field called `IsComplete`
reading `true` beside it invites an auditor who was not present to conclude that nothing about the
run was missing. In-memory types keep `IsComplete`, which is this codebase's convention for
*everything that should have been seen was seen*; **this file is a contract with a reader who knows
none of that.**

**A null `RungReached` in the file means nothing was observed** about that controller's security
posture — never that it refused protection.

**What a run did to a customer's forest outlives the console it was started from.** A capture that
read three domains from their PDC emulators needs to have said so somewhere durable.

---

## Checking one named controller

`NamedControllerCheck` proves a typed host by asking that host and nothing else.

Checking a typed host used to cost a full discovery — a bootstrap connection, the configuration
partition, the candidate list for every domain in the forest — to answer a question about one
machine (`F-S41-4`). **An operator correcting a typo in a nine-domain forest paid for the whole
forest each time he pressed the button.**

**It asks the host what it serves rather than asking the forest whether it should.** That answers the
question an operator actually asked: *is this machine one I can read this domain from.* A controller
the forest does not list can still answer that, and a controller the forest does list can still be
switched off. **The forest's list is a description written by replication; this is the machine
itself.**

**What it deliberately does not decide.** Whether the forest names this host stays separately
reported — a host that answers and serves the right partition while the forest does not list it is a
real and useful signal, not a refusal. Whether the run may *pin* it remains `ControllerSelection`'s,
and that refusal is unchanged.

A controller that answered and serves something else is refused here rather than at capture, because
**reading a domain from a controller that does not hold it produces an empty answer rather than an
error.**

---

## Starting a capture

`CaptureSession` is the composition root and the one way a capture is started, per `0039`.

**It decides nothing an operator could decide differently.** There is no scope and no choice of
transport. A caller supplies the run library root and whether to read or only check — and nothing
else. **A graphical surface is a caller of this, never a second implementation of it.**

**The run library root is required and has no default** (`0025`). A tool that decides for itself
where several gigabytes of evidence go is a tool that fills the wrong disk.

**Why the preflight loop is not a method on the session.** The session builds its own channel factory
and takes none, which is correct and means a loop written inside it could not be exercised without a
live forest. Taking the factory as an argument in `Preflight` puts the whole pass under test against
the controller model, and leaves the session's own surface unchanged.

---

## What is built

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| have every domain checked, even after the first one fails | `PreflightTests.EveryDomainIsAskedEvenWhenTheFirstOneFails` | |
| tell "was asked and said no" apart from "was never asked" | `PreflightTests.TheQuestionsAnUnreachableControllerWasNeverAskedAreRecordedAsUnasked` | |
| see how protected each domain's connection was | `PreflightTests.TheFileSaysWhichControllerServedEachDomainAndHowProtectedItWas` | |
| continue when a password settings container cannot be read, and know which domain it was | `PreflightTests.AnUnreadablePasswordSettingsContainerDoesNotStopTheRun` | |
| have every domain asked at once, and no controller asked two things at once | `PreflightTests.TwoDomainsOnOneControllerAreNeverAskedAtTheSameTime` | |
| be certain that pass is genuinely concurrent rather than concurrent in shape | `PreflightTests.DomainsOnDifferentControllersAreAskedAtTheSameTime` | |

**Verified in the lab.** 2026-09-xx, against `ad.lab` with `ba.ad.lab` and `ph.ad.lab`, one
controller per domain, no subnets declared.

---

## What this document cannot tell you

**How a deliberately excluded domain appears here.** `0063` decided that an exclusion and an
unreachable domain are two different events which the product never renders alike. The seam is drawn
and **not yet built** — there is deliberately no member here to put one in.

**Whether ten seconds is the right timeout.** It is the value the previous product's preflight used
per controller and the one thing about that component the map recorded as worth keeping. It has not
been re-derived.
