# S-37 — A preflight that reports every domain

## What this session is for

**Make `CaptureSession.ValidateAsync` answer every question for every domain and return the
answers, instead of returning the first failure it meets.**

This is the prerequisite for any preflight surface. Until it is done, no screen can show what
preflight found, because there is nothing per-domain to show.

## Why it is next

[`0048`](../../decisions/0048-preflight-proves-a-controller-before-a-run-commits.md) decided it:
*"Every question is answered for every domain before any is allowed to stop the run."* The code does
the opposite. It is a small change and it unblocks both the New Audit wizard and the run detail
view.

## What the code does today

`CaptureSession.ConfirmEveryDomainIsReachable` walks the domains and returns on the first bad one.
Its own summary says so - *"returning the first failure or null when every one of them answered."*

```csharp
foreach (var unit in plan.Units.Where(u => u.Kind == NamingContextKind.Domain))
{
    var opened = connections.Connect(unit);
    if (!opened.IsSuccess)
        return Result<CapturePlan>.Failure(opened.Error!);

    using var channel = opened.Value!;

    var confirmed = unit.ConfirmServedBy(channel.NamingContextsServed);
    if (!confirmed.IsSuccess)
        return Result<CapturePlan>.Failure(confirmed.Error!);
}
```

## The three gaps

1. **It stops at the first failure.** Nine domains with three faults costs four validate passes to
   discover three facts that were all knowable in one. Each pass repeats discovery and reconnects to
   every healthy domain.
2. **There is no per-domain result.** `ValidateAsync` returns `Result<CapturePlan>` - the plan, or
   one error. A table with a row per domain cannot be bound to anything, because nothing of that
   shape exists.
3. **The connection rung is measured and discarded.** `ValidateAsync` constructs a
   `ConnectionSecurityLog`, walks the ladder with it, and throws it away. Which rung each controller
   answered on - the whole point of
   [`0018`](../../decisions/0018-connection-security-is-an-ordered-ladder.md) - never reaches the
   caller, even for domains that succeeded.

## What to build

- **A preflight report.** One entry per partition: the controller, whether it answered, which rung
  the connection reached, whether it serves that partition, and whether the Password Settings
  Container was readable (the fourth question in `0048`).
- **A loop that continues**, collecting outcomes rather than returning on the first failure.
- **`ValidateAsync` returns the report.** Whether the run may proceed becomes a question asked *of*
  the report rather than the report's only content.

**Call sites to adjust:** `CaptureSession.RunAsync`, which validates before capturing; the CLI's
`--validate-only` path and its `Describe` output; and whatever surface consumes it next.

## What is already settled and must not be re-opened

Cite these rather than restating them, and do not re-derive them:

- [`0048`](../../decisions/0048-preflight-proves-a-controller-before-a-run-commits.md) — preflight's
  four questions, that answers are reported together, that preflight is **sequential on purpose**,
  that the pin is written to `preflight.json` before capture, and that there is **no disk-space
  check**.
- [`0036`](../../decisions/0036-capture-never-requests-the-sacl.md) — the SACL is never requested,
  so nothing here depends on `SeSecurityPrivilege` and no finding concerns audit configuration.
- [`0040`](../../decisions/0040-a-failed-domain-is-read-again-from-another-controller.md) — what
  happens after a failure, and that a controller never changes within an attempt. **Not to be
  amended**; it already says this.
- [`0050`](../../decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md) —
  where candidates come from. **Not in this session**, but the report's shape should not make it
  awkward later.
- [`0049`](../../decisions/0049-an-operator-may-exclude-a-domain-under-attestation.md) — an operator
  may exclude a domain under attestation. `0017` does **not** govern domain selection; it governs
  organisational units. This was got wrong twice.

## Not in this session

Controller discovery from the configuration partition (`0050`), the domain exclusion surface
(`0049`), organisational unit exclusion (refused by `0017`), and the unattended-run policy, which
`0048` names as deferred rather than defaulted.

## Owed by the end

A preflight report type with a test that every question it names has a consumer, and that a forest
with several faults reports all of them from one pass rather than one per attempt.
