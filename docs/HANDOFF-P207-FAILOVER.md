# Session handoff — build `0040` next-controller failover (P-207)

**Written 2026-09-13.** Repository at `1542536` + `b1f2da7`, both pushed, working tree clean.
CI green on `1542536`.

**`main` is red, and it is not a regression.** `b1f2da7` failed CI on
`ParallelDomainCaptureTests.DomainsOnDifferentControllersAreReadAtTheSameTime` — *"The domains
never overlapped, so they were read one after another."* **That commit changed one markdown
file and no code**, so the fan-out cannot have broken; the two-core runner was too starved for
two domains to hold the processor at the same moment, on a run where neighbouring tests took
three to five minutes each. It passes locally in 15 seconds. Recorded as `P-220` with the fix
direction: make the overlap observable with a barrier rather than by racing the scheduler.
**Do not widen a timing window or add a retry** — both leave a test that passes when the
fan-out is broken.

Expect a red `main` until `P-220` is fixed, and do not read it as your own breakage. Check CI
after pushing, opportunistically, with one non-blocking call:

```
gh run list --branch main --limit 1 --json headSha,conclusion
```

---

## Read before anything else

- `docs/WHAT-THE-PRODUCT-IS.md` — what SecureAD is, the run pipeline, the five commitments,
  and § *The forest this is built for* (~347,000 objects, 5.9M ACEs, nine domains, against a
  lab of 8,383). Measure against that shape, never the lab.
- `.github/copilot-instructions.md` — how to work here, and the five things that stop the work.
- `docs/PUNCH-LIST.md` — the queue. Rows `P-207`, `P-211`…`P-219` are this review's output.
- `docs/decisions/0040-a-failed-domain-is-read-again-from-another-controller.md` — the decision
  being built. Accepted 2026-08-14, never implemented.

The owner is an AD/security administrator, not a developer. Make the engineering calls
yourself and explain the consequence in plain language; ask him about product behaviour,
wording, and priorities. **Get explicit approval before changing any UI wording or layout.**

---

## What just shipped, so it is not redone

`1542536` fixed three SYSVOL correctness defects found in Scout's capture review of 2026-09-13:

| Was | Now |
|---|---|
| A policy file that would not parse was reported as **fully read** — judging then assessed an absent setting as a finding-free policy | The parse failure marks coverage; the policy reports `PartiallyRead` and names the file |
| An enumerated file that vanished before acquisition left coverage **complete** | A listed-then-unopenable file is recorded as a gap |
| A duplicate descriptor threw a SQLite unique-constraint exception, **aborting the whole capture** after the LDAP hours and before sealing | Each descriptor path is acquired once per policy; a second attempt is refused, not overwritten |

All three were fixed at the acquisition. **No SYSVOL exception is caught and no bundle is
sealed over an integrity failure** — Scout's governing rule for the batch, and it still
governs: *unreadable evidence may be explicitly partial; broken evidence persistence must
not masquerade as successful capture.*

`b1f2da7` moved the nine unfixed review findings onto the punch list and deleted
`next/CAPTURE_REVIEW.md`. Do not recreate that file. The punch list is the queue.

**A warning worth carrying.** Two of the tests written to prove those fixes were not measuring
what they claimed — each fixture had a *second*, unrelated gap, so the outcome assertion passed
against a capture with the fix removed. Only mutation testing found it. **A fixture with more
than one thing wrong cannot prove which one the check saw.** That is the third time this
repository has produced a check that passes while measuring nothing, and the first time it
happened inside tests written to prevent it. Mutate every new check, and rebuild explicitly
either side (`P-205`: the test runner does not always rebuild the product).

---

## The work: `P-207`, ADR `0040`

**The owner has ruled this is built before the production run.** It is the largest readiness
gap left in capture.

### What is wrong, in plain terms

If a domain controller dies two hours into an overnight nine-domain audit, **the whole run
ends with no bundle** — even though the forest names other controllers that could have served
that domain. The product already discovered them, already ranked them, and already shows them
to the operator in preflight as "failover". Nothing ever walks the list.

### What is already built (verified 2026-09-13, not assumed)

- **The ranked candidate list exists.** `ControllerSelection` produces
  `DomainSelection.Failover` — the remaining candidates in rank order (same site first, then
  not holding an FSMO role, then lexically by host for determinism).
- **It reaches the operator.** `PlanPreview.cs:49-51` prints it; `Preflight.cs:284` carries it
  as `Alternatives`.
- **`DiscoveryWiringTests.TheFailoverListIsRankedAndShownInThatOrder` is honest about the
  gap** — its own remark says *"Nothing walks the list. `0040`'s retry is not implemented."*
  That is the acknowledgement to retire when this lands.

### Where it stops

`Failover` appears **nine times in `SecureAD.Audit`, and not once under `Capture/`.**
`CapturePlan.For()` takes the pinned controller and drops the list. `CaptureUnit` carries a
single immutable `DomainController`, and `PartitionCapture.ReadAsync` (L104) loops
`ReadOnceAsync(unit, …)` with the *same* unit — so the restart retries the machine that just
failed. `PartitionCapture` L146-152 then actively **refuses** a channel to a different
controller for the same unit (`ConnectionIsToAnotherController`).

**That guard is correct and `0040` says to keep it.** The decision is explicit: *"A controller
is never changed during an attempt… the check in `PartitionCapture` that refuses a connection
pointing anywhere else stays exactly as it is. A second attempt is a **new** pairing of domain
and controller rather than the same one mutated."* Do not loosen it. Build the failover one
level out, as a new `CaptureUnit`.

### The part that looks hard and is not

`0040` requires that **everything the failed attempt wrote is discarded** — "not merged, not
retained, not marked… there is no seam, because there are never two partial reads of one
domain in a bundle." The decision deliberately does not name a mechanism, warning that
`0041`'s parallel interleaved writes would defeat the obvious single-threaded one.

**`0041` already solved it.** Each domain reads into its own shard file
(`evidence.shard-{n}.db.partial`), and `CaptureRun.cs:296` records the existing rule: *"A failed
domain's shard is simply not merged."* A discarded attempt is a shard file that is never
absorbed. Everything except the trustee table is private to its shard. So the retry writes a
fresh shard, the dead one is deleted, and `0040`'s hardest clause costs almost nothing.

**Check this before relying on it:** confirm shard numbering survives a second attempt for one
domain — `CaptureRun.cs:265-271` pairs shard indices to domains *by plan position* before any
reading starts, which is deliberate (stable regardless of which controller answers first). A
retry must not collide with another domain's index or silently reuse a number whose file still
exists.

### Bounded by decision

- Retries inside an attempt (`S-10`) run first: three at the request, then one restart on a
  fresh connection to the **same** controller. Only when those are exhausted does the
  controller change.
- **The candidate list is finite and its exhaustion ends the run** per `0003`. No re-discovery
  at the moment of failure, no unbounded search — a genuinely broken domain must fail in
  bounded time rather than grinding through candidates for hours.
- **The bundle must say what happened**: which controller read each domain, and that an earlier
  one was attempted and failed. `0040` is explicit that a run which quietly succeeded on the
  second controller hides a customer's controller going down mid-audit, which is itself worth
  knowing.

### Suggested shape

1. Carry `Failover` through `CapturePlan.For()` into the unit, or alongside it.
2. Do the controller change **above** `PartitionCapture.ReadAsync` — probably in
   `CaptureRun.ReadOneDomainAsync` — by constructing a new `CaptureUnit` for the next
   candidate. Leave `ReadAsync`'s restart loop and the `ConnectionIsToAnotherController`
   guard untouched.
3. Discard the failed attempt's shard; write the new attempt into a fresh one.
4. Record the attempt and its failure in the run log and in the bundle.
5. On exhaustion, fail the run with the **original** reason, not a synthetic one.

`LdapDirectoryChannelFactory` holds no per-controller cached state — each `Connect` opens a
fresh connection and renegotiates — so nothing needs invalidating on failover.

### Tests it must have

- Mutate every new check. A failover test that passes when the failover is removed is worse
  than no test.
- A domain whose first controller fails terminally is read from the second, and the bundle
  contains **one** continuous read with no trace of the first.
- Exhausting the list ends the run, in bounded time, naming the original failure.
- The `ConnectionIsToAnotherController` guard still fires within an attempt.
- Retire the `DiscoveryWiringTests` "nothing walks the list" remark only when it is false.

---

## After `P-207`

In the owner's stated priority order for a production run:

- **`P-213` (`CAP-006`)** — preflight prints *"Every domain answered. This run would proceed."*
  and capture then refuses the same forest, because a declared domain with no candidates
  contributes no row and so cannot block. A check that is believed and then contradicted is
  worse than no check.
- **`P-211` / `P-212` (`CAP-004`/`CAP-005`)** — the window and the command line disagree about
  what a domain is called (naming context vs DNS name). A controller the operator picked is
  rejected as not in this forest; and a domain with no reachable controller loses its real
  name, so the exclusion attestation the operator was asked for is refused. Fix both together;
  test through the **real** launcher-to-discovery boundary, because the GUI and discovery
  fixtures each use one representation and neither proves they agree.
- **`P-215` (`CAP-008`)** — a run that can no longer be sealed keeps reading for hours.
- **`P-216` (`CAP-009`)** — stop is ignored in the last moments before sealing and the run
  reports success.
- **`P-172` remainder** — the run boundary still owes a **durable failure outcome** when an
  exception escapes and the destination is still writable. Deferred deliberately last session;
  it pairs naturally with `P-215`/`P-216`.
- **`P-214`, `P-217`, `P-218`** — a busy controller reported as refusing secure connections;
  a failed delete that damages a bundle while saying nothing was touched; one unreadable file
  hiding the entire run library.
- **`P-208`** — the merge is the least-proven code in the product and has never run against a
  real forest. It was *reviewed without a confirmed finding, which is not certified correct.*
  Its failure mode is a permission attributed to the wrong account. The row lists the
  association-level tests Scout specified.
- **`P-209` / `P-210`** — `gpo_file_error` has no reader, and coverage reasons cap at three.
  Both need an owner decision, not code.

`P-219` (`CAP-011`) is **deferred by owner ruling** — single-operator tool. Revisit only if the
product gains scheduled runs or a second concurrent operator.

**`P-220` is not from the capture review** — it is the CI flake described at the top. Worth
taking early if a red `main` will make it hard to tell your own breakage from the noise.

---

## Working rules that bit last session

- **Punch-list rows are one very long single line**, 5 pipes. Edit with .NET
  `ReadAllText`/`Replace`/`WriteAllText` using `New-Object System.Text.UTF8Encoding($false)`
  and **absolute paths** (.NET file APIs ignore PowerShell's `Set-Location`). Verify pipe
  count and encoding after every edit. `replace_string_in_file` has twice silently deleted
  text beyond its match in these long rows.
- **Every verification command needs a self-test.** A `Select-String -SimpleMatch 'a|b'` and a
  test filter naming the wrong namespace both reported success while matching nothing, in this
  session. Prove the check can find something before trusting that it found nothing.
- Full suite: `dotnet test SecureAD.Next.sln -c Release --nologo` from `next\`. **4,607 tests,
  0 failed** at handoff.
- Do not block on CI after pushing. Check it opportunistically.
- Commit messages carry the reasoning. Documents do not.
