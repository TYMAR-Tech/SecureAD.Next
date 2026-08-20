# S-37 — A preflight that reports every domain

> **This records session S-37 as of 2026-08-11. Nothing here states current behaviour.**  
> It is kept for the reasoning it carries, not as documentation. See [`docs/history/README.md`](README.md).

**Ledger row:** `A8` — preflight validation. **Status after this session:** Done.
**Governing record:** [`0048`](../decisions/0048-preflight-proves-a-controller-before-a-run-commits.md).

This document is discussion, not authority. Where it disagrees with the code, the code wins and the
disagreement is a finding.

## What was wrong

`CaptureSession.ConfirmEveryDomainIsReachable` walked the domains and returned on the first bad one.
Its own summary said so — *"returning the first failure or null when every one of them answered."*

Three things followed from that, and all three are now fixed.

**One fault per attempt.** Nine domains with three faults cost four validate passes to discover
three facts that were all knowable in one, each pass repeating discovery and reconnecting to every
healthy domain. `0048` requires the opposite: *"Every question is answered for every domain before
any is allowed to stop the run."*

**Nothing per-domain to show.** `ValidateAsync` returned `Result<CapturePlan>` — the plan, or one
error. A table with a row per domain could not be bound to anything, because nothing of that shape
existed. That blocked both the New Audit wizard and the run detail view.

**The connection rung was measured and discarded.** `ValidateAsync` built a `ConnectionSecurityLog`,
walked the ladder with it, and threw it away. Which rung each controller answered on — the whole
point of [`0018`](../decisions/0018-connection-security-is-an-ordered-ladder.md) — never reached the
caller, even for domains that succeeded.

## What was built

`Connect/Preflight.cs` is the pass. It takes a channel factory and a plan, asks all four questions
of every domain, and returns every answer. `Connect/PreflightReport.cs` is what it returns.
`Connect/PreflightFile.cs` writes that down as `preflight.json` before any capture traffic.

`ValidateAsync` now returns the report. **A success from it means every domain was asked, not that
every domain passed.** Whether the run may proceed is `PreflightReport.RunMayProceed`, asked *of*
the report.

### Two shapes that carry a decision

**A controller nothing answered from has no rung, and cannot be given one.** `RungReached` is
nullable rather than defaulted to a worst case. This is finding `F-S35-1` made structural: a ladder
walk that was answered by nothing has observed nothing, and reporting it as a controller that
refuses protected connections is a security claim about a customer's forest that the product did not
measure. The two faults have opposite remedies — correct the name, or fix the controller's
configuration.

**`PreflightAnswer` has three members, not two.** A question preflight never reached and a question
answered *no* are different, and a boolean would have to say `false` to both.
[`0002`](../decisions/0002-absent-view-means-degraded-run.md) forbids collapsing them.

## What stops the run and what does not

Not restated from the records; this is where the two threads meet.

A domain that **could not be read** — unreachable, or served by a controller that does not hold the
partition — stops the run. That is [`0003`](../decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md),
and [`0052`](../decisions/0052-the-domain-is-the-only-unit-of-scope.md) forbids
recording it as anything a customer chose. It stops the run *after every domain has been asked*, and
`PreflightReport.Refusal()` names all of them.

A domain whose **Password Settings Container could not be read** does not stop the run. `0048` states
that Enterprise Admins is not required and that the supported posture is an ordinary account with
read access delegated per domain; a run that refused to start over one container would refuse that
posture. What the answer buys is paid later and in the open — the report says it could not tell,
rather than that the domain has no fine-grained password policy when it has several. **This reading
of `0048` was put to the owner and confirmed on 2026-08-15.** It is the one part of this session's
behaviour that no record states outright.

## What is deliberately absent

`0048` says `preflight.json` names, per domain, the ranked candidate list and whether the pin came
from ranking or from an operator override. Neither is written.

**This was true of the forest as `S-37` left it and is no longer true of the code.** At the time,
candidate lists were still
[`0050`](../decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md)'s to build,
the override was an operator surface nothing implemented, and every domain had exactly one
controller reached through its DNS name - so an empty list or a defaulted origin in a file an
auditor reads would have put a measured-looking value where nothing was measured.

`S-39` built the candidate lists and `S-40` wired them into the run. Both facts now exist per domain
and `preflight.json` still does not carry them, which is recorded as a finding at
[`S-40`](S-40-wiring-discovery-into-capture.md) rather than left reading as a design choice.

## The binding

`PreflightTests`. Fourteen tests, and each of the four questions is exercised in both directions —
a container read and a container refused, a controller that serves its partition and one that does
not, a controller that answered and one that did not.

`EveryFactPreflightRecordsIsWrittenDown` is the guard the session owed: every constructor parameter
of `DomainPreflight` must appear in `PreflightDomainRecord`, because a run that dies before sealing
leaves `preflight.json` as the only account of what preflight proved. It carries a scanner self-test
(`TheCheckThatEveryFactIsWrittenDownWouldNoticeOneThatIsNot`), for the reason
`docs/next/README.md` § Gates gives.

Four guards were mutation-tested and all four were observed failing before being restored:

| Mutation | Caught by |
| --- | --- |
| Restore the early return on first failure | `EveryDomainIsAskedEvenWhenTheFirstOneFails`, `EachDomainCostsOneConnection`, `TheRefusalNamesEveryDomainThatFailed` |
| Give an unreachable controller a rung | `AControllerThatAnsweredNothingIsGivenNoRung`, `TheFileSaysWhichControllerServedEachDomainAndHowProtectedItWas` |
| Refusal names only the first blocking domain | `TheRefusalNamesEveryDomainThatFailed` |
| Add a recorded fact the file does not carry | `EveryFactPreflightRecordsIsWrittenDown` |

**One observation worth keeping.** For the third mutation, the assertion on the count — *"2 of 4
domains"* — still passed, because the count is computed from the blocking list while the sentence is
built from it separately. Only the assertion naming `DC=elsewhere,DC=example,DC=com` caught it. Both
assertions are load-bearing and neither should be removed as redundant.

## Not in this session

Controller discovery from the configuration partition (`0050`), the domain exclusion surface
([`0052`](../decisions/0052-the-domain-is-the-only-unit-of-scope.md)), organisational unit
exclusion (refused by the same record), and the unattended-run policy, which
`0048` names as deferred rather than defaulted.

Finding **`F-S35-3`** also remains open and is recorded on the ledger row: the predecessor's
preflight was a second wall against a read-only domain controller, and nothing here asks that
question.
