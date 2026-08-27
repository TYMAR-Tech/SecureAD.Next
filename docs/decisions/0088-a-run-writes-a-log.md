# 0088 - A run writes a log, beside the evidence and outside the seal

Date: 2026-08-28
Status: Accepted.

Sits beside [0029](0029-a-run-that-ends-badly-says-so.md) and
[0039](0039-one-way-to-start-a-capture.md), which between them require a run to end with something an
operator can read in the morning. This says the same about a run that has *not* ended: while it is
going, and when it stops in a way nobody anticipated.

## Context

The product had no logging of any kind. Not a reduced amount - none.

**What that cost, measured on a real defect.** Stage 2a crashed on the first multi-domain forest it
was pointed at, and this is the whole of what the operator was given:

```
The run stopped on an error the product did not expect: SQLite Error 19:
'UNIQUE constraint failed: sid_identity.sid_id'.
```

No run identity. No phase. No indication which of 4,273 principals caused it, out of a forest with
three domains and 32 SIDs held by more than one object. Diagnosing it took ad-hoc SQLite queries
against the sealed evidence to find the duplicate, and a second set against the derivation store to
prove the fix. Every fact needed was in memory at the moment it threw, and every one was discarded.

**The predecessor had this and it was not the problem.** `RunLogService` gave each run a timestamped
folder under `%LOCALAPPDATA%/SecureAD/Logs/runs/`, a run-scoped `ILogger`, a `run-summary.json` at
the end, and pruning at 25 folders. `DirectCaptureRunner` alone logged in 36 places.

What gate 1 indicts is narrower than the whole idea, and worth quoting exactly:

> that is how progress, cancellation and **the performance log** all became optional and unused

The defect was that it could be omitted, so it was. That is a fact about the parameter, not about
logging.

## Decision

**A run writes `run.log` beside the evidence, outside the seal.** One file per bundle, appended to by
capture, then deriving, then judging, so a whole run reads top to bottom in the order it happened.

**It sits outside the seal because it cannot sit inside one.** It is written *during* the run the
seal is taken at the end of. `run-outcome.json` and `preflight.json` are already outside for the same
reason, and `the-bundle-on-disk.md` already says so.

**It is text, not JSON.** Fixed leading columns so an eye can scan down them, the error code alone as
a greppable handle, and trailing `key=value` pairs for detail:

```
2026-08-28T11:06:00Z  INFO   MembershipAndNesting    read 4,273 objects in 2.1s
2026-08-28T11:06:02Z  ERROR  MembershipAndNesting    Derivation.SidIdentityDuplicate sid=S-1-5-32-544 domain=ba.ad.lab
                                                     UNIQUE constraint failed: sid_identity.sid_id
```

**The detail stays on the headline; only the description is pushed below it.** This was got wrong
first and the tests caught it. A line found by searching for `sid=S-1-5-32-544` has to carry its own
timestamp, level and phase, or the search returns an orphan and the reader has to hunt upwards for
the context — which is most of what the format was chosen for. A description is prose, is long, and
is not something anybody searches for, so it is the one thing that goes on its own line.

**Nothing is redacted.** The log names distinguished names, SIDs and domains, which is precisely
what the bundle lying next to it already holds. Redacting would remove the only detail that makes it
worth keeping - the defect above was a specific SID in a specific domain - and would not protect
anything, because the sensitive artefact is the evidence and it is already there.

**It is obliged, not offered.** `IRunLog` is a required parameter of `Stage2aRun.Derive` and
`JudgingRun.Judge`. Never defaulted, per gate 1. A caller with nowhere to write passes an explicitly
named discard, the way `Stage2aRun.Unwatched` already works for progress - a name says somebody
decided, where a null says nobody did.

**Capture owns its log rather than being handed one, and that is not an exception to the rule.**
This was drafted as a third required parameter and the code refused it: the bundle directory does
not exist until `RunLibrary.CreateRun`, so no caller could open a log beside a run that has not been
made. Deriving and judging are handed a bundle that already exists; capture is the stage that makes
one, so capture opens the log itself.

What that costs is worth stating rather than hiding. Every refusal before the directory exists - a
forest that could not be found, a domain nobody attested for, a controller that refused every rung -
is returned to the caller and never reaches a file. Those are exactly the runs where no bundle
exists at all, so [`0029`](0029-a-run-that-ends-badly-says-so.md)'s `run-outcome.json` is what
speaks for them, and `preflight.json` holds what preflight established.

**A log takes notes and errors, and invents no third vocabulary for how much a line matters.** The
log records two different things and the level in the file is derived rather than chosen:

| Written | Appears as | Where the level comes from |
|---|---|---|
| a note - a phase started, a count, a duration | `INFO` | it is not an error, so there is nothing to grade |
| an `AuditError` of `ErrorSeverity.Degraded` | `WARN` | the error's own severity |
| an `AuditError` of `ErrorSeverity.Failed` | `ERROR` | the error's own severity |

`ErrorSeverity` already answers *how much does this matter*, and its two members are exactly the two
an error can be: the operation continued having lost something, or it produced no result. A
`RunLogLevel` enum repeating `Degraded` and `Failed` beside a third value would be a second answer to
a question that has one, which is what gate 2 forbids. Widening `ErrorSeverity` itself is worse: it
is named for errors and documented as grading them, and an informational error is a contradiction.

So no concept is added to `CONCEPT-REGISTRY.md`, because no new question is being asked. It also
makes a whole class of nonsense unwritable - there is no way to log an informational failure, because
the two are different methods.

## Why not the alternatives

**JSON Lines.** Considered first and rejected. Nothing reads these programmatically; the reader who
matters is a person holding a bundle a customer emailed over. A record needing a tool to be legible
fails 0029's standard on its own terms, and the only thing JSON buys over `key=value` is nesting,
which a flat `AuditError` does not need.

**`%LOCALAPPDATA%`, as the predecessor did.** It does not travel. A bundle sent for diagnosis arrives
without the log that explains it, which is exactly the position this record was written from. It is
also *worse* for privacy rather than better: customer data would be written to a machine-wide
location outside the artefact everyone already treats as sensitive.

**Sealing the log.** Impossible without changing when a run seals, and pointless: the log is
diagnostic, not evidence. Nothing concludes anything from it.

**Logging only in the launchers.** The smallest change, and it would not have caught this defect. The
information that was missing lived inside a phase.

## Consequences

Three coordinator signatures gain a required parameter, and every caller and test changes with them.
That ripple is the decision working rather than a cost of it: an `IRunLog` that could be left out
would be left out, which is the predecessor's performance log again.

**Scope is held deliberately narrow to start.** Phase boundaries, every `AuditError` a coordinator
constructs, and every exception it catches. Not per-object tracing - a line per object over a forest
is a file nobody opens twice, and the failure this record is about was at a phase boundary.
