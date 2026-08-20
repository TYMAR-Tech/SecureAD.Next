# S-36 — How the app chooses a domain controller, and proves it

> **Corrected 2026-08-14.** The section below headed *What is already settled and must not be
> re-opened* restated [`0017`](../../decisions/0017-capture-reads-the-whole-forest.md) as forbidding
> a choice of **domains**. It does not. `0017`'s subject is operator-configurable exclusion of part
> of a directory's **contents** — organisational units and containers — and its own closing line
> already separates a container that cannot be read from a decision a customer made. Whether an
> operator may exclude a whole **domain** is a different question, and `0017` does not answer it.
> That question is [`0049`](../../decisions/0049-an-operator-may-exclude-a-domain-under-attestation.md).
> The restatement here caused the same wrong objection to be raised twice, which is why
> [`0040`](../../decisions/0040-a-failed-domain-is-read-again-from-another-controller.md) forbids
> restating a record rather than citing it.

## What this session is for

**Decide and build how a run selects the domain controller it reads each domain from, and prove
those controllers answer before hours of capture are committed to them.**

This is what the owner means by *preflight*. It is not a screen. The screen follows from it.

## Why it is the next session

The owner has ruled that the foundation comes before analysis: open the app, run an audit, see it
work, surface settings as they arrive. This is the front of that workflow and nothing else in it
can be trusted until this is settled.

It is also a genuine hole rather than an unbuilt feature. Five ledger rows — `A3` DC/GC name
resolution, `A4` DC selection policy, `A5` DC discovery, `A6` DC routing and failover, `A8`
preflight validation — are all *Decided, not started*, and between them they describe exactly this.
`A8` additionally owes a decision record and has never had one.

## What the rebuild does today

`ForestDiscovery.cs` sets each domain's controller to the domain's own DNS name:

```csharp
.Select(d => (d.NamingContext, d.DnsName, DomainController: d.DnsName))
```

So the product connects to `contoso.example` and reads that domain from whichever controller DNS
returns. There is no selection, no site affinity, no capability check, no record of which controller
actually answered, and no candidate list.

## The four findings this session answers

- **`F-S35-1`** — a host that cannot be resolved descends the security ladder and emerges reporting
  that the controller *"accepting nothing signed leaves its LDAP traffic open to alteration in
  transit"*. Nothing was reached and nothing was observed. That is a security claim about a
  customer's forest the product did not measure, which [`0002`](../../decisions/0002-absent-view-means-degraded-run.md)
  forbids. **The remedy belongs here**: unreachable and refusing-to-be-protected are different
  answers with opposite remedies.
- **`F-S35-2`** — [`0040`](../../decisions/0040-a-failed-domain-is-read-again-from-another-controller.md)
  requires a failed domain to be read again *on the next controller listed for it*, and states that
  *the candidate list is finite and its exhaustion ends the run*. There is no candidate list. `0040`
  deferred the mechanism deliberately; this session supplies it or `0040` cannot be honoured.
- **`F-S35-3`** — the predecessor refused to audit from a read-only domain controller, at two
  independent points, and neither was carried across. The rebuild cannot tell an RODC from a
  writable DC.
- **`F-S35-4`** — the predecessor's preflight recorded which controller actually answered. The
  rebuild records nothing, so a bundle cannot say which controller served each domain — which `0040`
  says it should.

## What the predecessor already solved, and is worth reading first

Not to port blindly. The owner's point is that a great deal was decided correctly in the old app and
the rebuild has been rediscovering it.

- `src/SecureAD.Core/Discovery/DcSelectionPolicy.cs` — pure and deterministic, no I/O. Filter
  candidates to reachable and writable, rank same-site first then lexically, return a primary plus
  an ordered failover list, accept a manual override that must still be eligible or it falls back.
  **That failover list is the candidate list `0040` assumes.**
- `src/SecureAD.Infrastructure/Ldap/DcDiscoveryService.cs` — enumerates candidates per domain and
  reads `msDS-isRODC`, withholding the writable capability from an RODC so it never becomes a
  candidate.
- `src/SecureAD.Infrastructure/Ldap/ForestDcPreflightService.cs` — per domain: connect, record the
  controller that answered, read the default naming context, re-check `msDS-isRODC` and refuse,
  verify the search base, with a timeout and structured failures.

## What is already settled and must not be re-opened

- **[`0017`](../../decisions/0017-capture-reads-the-whole-forest.md): capture reads the whole forest.**
  There is no choosing which domains to include. Scope is a reading-layer concern and a sealed
  bundle is never scoped. The predecessor's wizard had a domains-to-include step; it is gone, and
  this session does not bring it back.
- **[`0047`](../../decisions/0047-settings-are-per-user-and-per-machine.md): the run library path is
  the only setting.** The predecessor's capture-load, GPP-scan and cache-profile steps are not
  settings in this product. A manual controller override, if this session decides to have one, is a
  per-run choice and not a stored preference.
- **[`0039`](../../decisions/0039-one-way-to-start-a-capture.md): one entry point into capture.**
  Whatever preflight becomes, the window and the command line reach it the same way.

## Owed by the end

- A decision record for `A8`, which it has owed since `S-13`.
- Whether a candidate list is built from DNS SRV records, from the directory, or from the operator —
  and what happens when it is exhausted, which `0040` says ends the run.
- Whether an RODC is refused outright or read with a declared coverage failure. The predecessor
  refused. `0002` and `0017` both bear on this and the answer is the owner's.
- Whether the operator may override the controller for a domain, and whether an override that turns
  out to be an RODC is refused or falls back.

## Not in this session

The capture progress rendering (`J10`), the settings surface (`J15`), and run detail (`J12`). They
follow, and each is its own session.
