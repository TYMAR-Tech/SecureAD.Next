# 0048 - Preflight proves a controller before a run commits, and records what it proved

Date: 2026-08-14
Status: Accepted. Amended 2026-08-16 by this record's own amendments below - preflight asks several
controllers at once, and a pass an operator cannot stop is not acceptable.

## Context

Ledger row `A8` - preflight validation - was disposed **Rebuild** in
`S-13` and has owed a decision record ever
since. The map recorded preflight as one of the previous product's good decisions: *"Validating DC
reachability before committing to a multi-hour capture is cheap... and prevents the worst failure
mode this tool has."*

Part of it has already been built elsewhere. `B4` and `B6` took the paper half - `CapturePlan`
confirms every unit against the partition list a controller published, and
`CaptureUnit.ConfirmServedBy` exists for the live half and has never had a caller. What is left is
everything that needs a socket, and there is more of it than `S-13` listed.

Two findings from `S-35` are assigned to this row and are
answered here:

- **`F-S35-1`** - a host that cannot be resolved descends the security ladder and emerges reporting
  that the controller *"accepting nothing signed leaves its LDAP traffic open to alteration in
  transit"*. Every rung had failed with *the LDAP server is unavailable*. Nothing was reached and
  nothing was observed, so this is a security claim about a customer's forest that the product did
  not measure - the thing [`0002`](0002-absent-view-means-degraded-run.md) exists to forbid.
- **`F-S35-4`** - the predecessor's preflight recorded which controller actually answered. The
  rebuild records nothing, so a bundle cannot say which controller served each domain, which
  [`0040`](0040-a-failed-domain-is-read-again-from-another-controller.md) says it should.

Where the candidate list comes from, and how a controller is chosen from it, is
[`0050`](0050-the-candidate-list-comes-from-the-configuration-partition.md) and is not restated
here. This record is only about proving the choice before hours are spent on it.

## Decision

**Preflight is a gate that runs before capture and asks four questions of each domain's chosen
controller.** The answers are the run's licence to proceed.

1. **Can this controller be reached, and on which rung.** The ladder from
   [`0018`](0018-connection-security-is-an-ordered-ladder.md) is walked once per controller here,
   not at hour two. A run that would have to declare an allowance discovers it in its first minute.
2. **Are the credentials good.** The bind is the check; there is nothing else to write.
3. **Does this controller serve this partition,** asked of the live RootDSE rather than of a list
   somebody handed over. This is what `CaptureUnit.ConfirmServedBy` answers and the reason that
   method exists.
4. **Could the Password Settings Container be read.** One base-scope read of
   `CN=Password Settings Container,CN=System,<domainNC>` per domain.

**The fourth question exists because its failure is silent.** `msDS-PasswordSettings` objects carry
a restrictive default access control list - in practice Domain Admins only - and an account without
that access reads the container as *empty* rather than as *denied*. A run made by such an account
would report that a domain has no fine-grained password policy when it has several. That is the
same class of unmeasured claim as `F-S35-1` and the same record forbids it. Recording the answer
turns *"this domain has no fine-grained password policy"* into a statement the bundle is entitled
to make.

**This is the only capability preflight asks about, and it is deliberately not a privilege probe.**
Sampling objects to compute a readable-descriptor rate was considered and rejected: it costs real
time for a fuzzy number. Two things that would otherwise have justified one do not apply. The audit
half of a security descriptor is never requested at all, per
[`0036`](0036-capture-never-requests-the-sacl.md), so no finding depends on `SeSecurityPrivilege`.
LAPS is detected from its expiration timestamp rather than its password, and the timestamp is an
ordinary attribute, so no finding depends on reading a confidential one. What remains is one
container, and one read answers for it.

**A consequence worth stating plainly: Enterprise Admins is not required.** The supported posture is
an ordinary account with read access delegated on the Password Settings Container in each domain.
Enterprise Admins remains the option for an operator who would rather not delegate. The product
never writes, so what it needs is breadth of read and never power.

**Being unable to reach a controller and being able to reach one that refuses protection are
different answers, and preflight must not conflate them.** This is the `F-S35-1` remedy. A ladder
walk that never got an answer from any rung has observed nothing, and must report that it observed
nothing. Only a walk that was answered may describe what the controller accepts. The two have
opposite remedies - one is a network or naming fault, the other is a finding about the customer's
configuration - and a bundle that mistakes the first for the second accuses a customer of a
weakness on the strength of a typo.

**Every question is answered for every domain before any is allowed to stop the run.** A preflight
that fails at the first bad answer sends an operator round a loop discovering one fault per
attempt. All four questions are asked of all domains and the answers are reported together.

**Preflight is sequential.** N controllers at ten seconds each is a minute or two at the size of
forest this product operates on, against a capture measured in hours. The previous product's
four-way concurrency bought a saving nobody would notice at a cost `SerializedDirectoryAccessGateTests`
exists to prevent. **This is slower than the predecessor on purpose.** *Superseded by the amendment
of 2026-08-16 below; the rule this clause was protecting is not.*

**What preflight proved is written down before capture begins.** `preflight.json` is written into
the run directory before any capture traffic, and it names, per domain: the candidate list in the
order it was ranked, which controller was pinned, whether that pin came from ranking or from an
operator override, which rung the connection reached, and whether the Password Settings Container
was readable. This is `F-S35-4` closed. It is a file rather than a row because it exists before
`audit.db` does and survives a run that dies before sealing, which is the unattended case.

**A domain with no candidates and a domain whose candidates were exhausted are recorded as
different outcomes.** The first means the forest itself names no controller for that partition -
measured absence, and a finding about the forest rather than a failure of the run. The second means
controllers were named and none answered. `0050` explains why these are now distinguishable at all.
What happens after exhaustion is
[`0040`](0040-a-failed-domain-is-read-again-from-another-controller.md) and
[`0003`](0003-refuse-to-reanalyse-an-incomplete-capture.md), and is not restated here.

**Preflight does not check for free disk space.** `S-13` proposed a floor and conceded in the same
breath that it "makes no claim about whether the space is enough, because nothing could: a bundle's
size is dominated by how many access control entries hang off an object rather than by the object
count". The predecessor had already reduced its own check to advisory, with a test named
`WhenSpaceIsBelowTheThreshold_ThenTheCaptureStillStarts`. A check that cannot be wrong in a useful
direction is removed rather than kept for the look of it. **Watching the space fall during a
capture and stopping deliberately is ledger row `C13`, and is the half with the value in it.**

## Amendment, 2026-08-16: several controllers at once, and never one controller twice at once

**Preflight asks every domain at the same time.** The clause above - *preflight is sequential* -
is replaced. What is **not** replaced, and must not be read as replaced, is the rule it was written
to protect: **no controller is ever asked two things at once.** Those were always two different
statements, and only the first of them was ever load-bearing.

**Why the original clause was wrong about its own reasoning.** It justified serialization by the
cost being small - a minute or two - and by `SerializedDirectoryAccessGateTests`. The second
justification does not hold: that guard has never forbidden concurrency. Its own words are *"not
capture is single-threaded... reading several naming contexts at once, each on its own controller,
is several controllers each seeing a well-behaved serial client, and it is safe."* Serializing the
whole pass was therefore a stricter rule than the danger required, adopted because it was the
easiest way to be certain of obeying the real one.

The first justification does not hold either, now that the wizard runs preflight when the window
opens rather than on a press. A minute or two is cheap when it is spent inside an operation an
operator asked for. It is not cheap when it is the delay between opening a window and being allowed
to do anything in it, and it scales with the customer's forest: thirty domains at ten seconds each
is five minutes of a window that does nothing.

**The real rule is now held explicitly rather than inherited.** Turns are taken per controller, by
host name, in `PreflightDispatch`. Two requests in flight against one controller compete for a
single budget of paged-search state - `MaxResultSetSize` - and the controller resolves that by
discarding the oldest, so overlapping reads can truncate each other silently and the run reports a
forest smaller than the one it read. That is a wrong answer rather than a failure, which is why it
is guarded and not merely avoided.

**The turns are keyed on the machine, not on the domain, and that is deliberate.** A writable
controller holds one domain, so two domains sharing a pinned controller is not a shape Active
Directory produces - but `ControllerSelection` has no rule against it and will pin the same host
twice if handed a forest that declares one. A concurrency that is correct only because the directory
happens to be well shaped is a defect waiting for the forest that is not, and this product's whole
business is forests that are not well shaped.

**Two guards hold this, and each exists because the other can pass while measuring nothing.**
`PreflightTests.TwoDomainsOnOneControllerAreNeverAskedAtTheSameTime` proves no controller is asked
twice at once. `PreflightTests.DomainsOnDifferentControllersAreAskedAtTheSameTime` proves the pass
is genuinely concurrent - and it earned its place immediately, by failing on the first
implementation, which fanned the work out correctly and then ran the connections one after another
anyway because opening a connection is synchronous. Every same-controller assertion passed. The
pass was parallel in shape and sequential in fact, and without the opposite guard it would have
shipped looking correct and costing the full delay it was meant to remove.

## Amendment, 2026-08-16: a pass an operator cannot stop is not acceptable

Preflight now begins when the New Audit window opens, without a press. That makes it the first thing
that happens to an operator rather than something he asked for, and it reaches every domain in the
forest over a network that may be slow, partitioned, or waiting on a name that will never resolve.

**Any long-running action this product starts gives the operator a way to stop it.** This is not
weighed case by case. A window that has begun contacting thirty domains and offers no way out
leaves killing the process as the only exit, and a product that has to be killed teaches an operator
that it cannot be trusted with the machine it is auditing.

**A stopped pass reports what it had, and never presents it as what it found.** Cancellation is not
an answer, and a domain that was never reached is *not asked* rather than *unreachable* - the
distinction [`0002`](0002-absent-view-means-degraded-run.md) exists to enforce, applied to a pass
the operator himself ended.


The worst failure mode this product has - hours of capture spent against a controller that was
never going to work - is paid for in the first minute instead. That was the predecessor's insight
and it is kept.

A bundle can now answer *"which controller served this domain, and how well protected was the
connection that read it"*. It could not before.

An under-privileged run is no longer silently wrong about fine-grained password policy. It is
either correct or it says it could not tell, and the difference is one boolean per domain.

**One question is deferred and is not decided here.** An unattended run that reaches a domain it
cannot read has nobody present to state a posture for it. Whether such a run stops, or proceeds
under a policy the operator declared before leaving, is unresolved. It is named rather than
defaulted, because a default chosen by omission here would be a posture the product invented on a
user's behalf - which is what `Resolve` was built to refuse in the predecessor and what
[`0002`](0002-absent-view-means-degraded-run.md) forbids in this one.

Nothing may restate this record. Rows, comments and notes cite `0048`.
