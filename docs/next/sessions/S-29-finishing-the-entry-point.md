# S-29 — Finishing the entry point

## Why this is a second prompt rather than a continuation of `S-28`

[`S-28`](../../history/S-28-the-entry-point.md) scoped `A9` as roughly fifty lines of wiring and recorded the
cross-reference read as "known-provisional, and not this session's job". Both were reasonable and
both are now wrong, so that prompt would misdirect anyone who read it. It is left as written,
because a prompt is the record of what a session was told.

What changed: wiring the four pieces together and pointing them at a forest with more than one
domain produces a bundle covering one domain and reporting itself complete. That is `F-S28-1`, and
the fix — reading the forest's own cross-references — is now the centre of the work rather than a
deferral.

## The state of the tree

Read [`S-28`'s slice document](../../history/S-28-the-entry-point.md) first. It carries both findings.

**Done, and passing:**

- [`0040`](../../decisions/0040-a-failed-domain-is-read-again-from-another-controller.md) and
  [`0041`](../../decisions/0041-capture-reads-domains-in-parallel.md), with `docs/DECISIONS.md`
  regenerated and rows `A6`, `B5` and `B7` citing them. **Both are decided and deliberately
  unbuilt.**
- `CaptureSearchRequestFactory.ForCrossReferences` — one-level search of the Partitions container.
- `Connect/ForestPartitions.cs` — reads `crossRef` objects and classifies each partition from
  `systemFlags`. **Internal, not public**, because gate 4 fired on its collections and the exemption
  route is closed to anything carrying a `Read` member. It is reached through `ForestDiscovery`.
- The `systemFlags` rule is verified against Microsoft's definition rather than remembered: a domain
  carries both `ADS_SYSTEMFLAG_CR_NTDS_NC` (`0x1`) and `ADS_SYSTEMFLAG_CR_NTDS_DOMAIN` (`0x2`).

**Not done:** everything from the controller model onwards. `ForestDiscovery` still guesses from the
shape of a name, `CapturePlan` still pins one controller to every unit, and nothing runs.

## Start here, and do not skip it

`F-S28-2`. `ForestDiscoveryTests.APublishedPartitionIsAccountedFor` asserts `plan.IsComplete` and an
empty `NotRead` against a `ControllerModel` publishing exactly the three partitions it plans — so it
passes while measuring nothing, and it is the test positioned over `F-S28-1`.

**Nothing later in this session means anything until the model contains a case the assertion can
fail on.** The model needs an application partition it publishes and an answer to the cross-reference
search. Mutation-test in both directions and say which were observed.

This is the third check of its kind in this repository, after gate 5's original wording and the `S-2`
document guard. See `docs/next/README.md` § Gates.

## The work

1. Give `ControllerModel` a DNS application partition and a `crossRef` answer, and rewrite the
   coverage assertion to name the partition it expects left unread.
2. Replace `ForestDiscovery`'s name-shape guess with `ForestPartitions`, keeping its RootDSE read for
   configuration and schema. This finishes `A7`.
3. Change `CapturePlan.For` to take a controller per domain, confirm each unit against the controller
   that will read it, and compute `NotRead` against the forest's declared partitions rather than
   against the list it planned from. **That subtraction is `F-S28-1`.** Prove it with a test that
   fails on the old arithmetic.
4. Build `A9`, the composition root: `RunLibrary`, `LdapDirectoryChannelFactory`, discovery,
   `CaptureRun`.
5. Create the console executable — `--library`, `--controller`, `--validate` — and add it to
   `SecureAD.Next.sln`. Argument parsing lives there and nothing else does, per
   [`0039`](../../decisions/0039-one-way-to-start-a-capture.md): a window must be able to drive the
   same entry point later.

A domain is reached through the `dnsRoot` its cross-reference carries, so the operator names one
controller and no per-domain arguments exist. **This is a lab-grade choice, and it is recorded as
such**: it gives *a* controller in the domain rather than a chosen one. Pinning controllers
explicitly is the config file, which the owner deferred until a GUI can generate it — hand-typing one
now would put typos into the first real run.

`--validate` connects, discovers, and tries each domain's controller without reading objects. It is
what makes the lab session productive: ten seconds to learn the run will work, rather than two hours.

## What governs it

- [`0039`](../../decisions/0039-one-way-to-start-a-capture.md) — one entry point, taking the run
  directory it is given, completing unattended.
- [`0025`](../../decisions/0025-the-run-library-is-a-managed-root.md) — the root is configuration and
  the operator supplies it. **There is no default and must not be one.**
- [`0018`](../../decisions/0018-connection-security-is-an-ordered-ladder.md) — no prompt at the
  moment of failure. **The unprotected-connection allowance is not exposed**: the owner decided to
  refuse until a real controller shows it is needed.
- [`0017`](../../decisions/0017-capture-reads-the-whole-forest.md) — the sealed bundle is never
  scoped, and a partition the run could not reach is a coverage failure that is stated.
- [`0003`](../../decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md) — capture is fail-fast.

## Out of scope

Parallel capture (`0041`) and controller failover (`0040`) are decided and are **not built here**.
The config file. The read side (`D`, `E`). The run library catalogue (`F12`–`F16`). A GUI, which the
owner wants after a real capture and which is a caller of this entry point rather than a second one.

## Then: a real capture

The owner runs it against a lab of one empty root domain and two children — the shape that would have
demonstrated `F-S28-1`. **Hand him the exact command lines.**

Five observations are owed against **B20** and become reachable here: the wire spelling of a ranged
attribute name (`F-S7-37`), whether a controller tolerates a base-scope search between two pages
(`F-S7-39`), what a client sees when a paging bookmark is evicted (`F-S7-40`), the credential
child-object measurement (`F-S7-26`), and a controller declining a rung.

**Expect the first real run to fail somewhere interesting.** That is what it is for.

## Rules that still bite

- Decisions are stated once, in `docs/decisions/`. Rows and comments cite; they do not paraphrase.
- Mutation-test any new or changed guard in both directions and say which were observed.
- A ledger row is edited with `next/tools/Replace-InventoryRow.ps1`, never by hand.
- After any scripted edit, check `git diff --numstat` — the shell strips a UTF-8 BOM.
- Long PowerShell goes in a script file under `$env:TEMP`, invoked with a short command.

## Finish by

- `A7` and `A9` built, and a run reaching a real controller
- `F-S28-2` closed, with the mutation directions recorded
- Every new public type in [`SURFACE-REGISTER.md`](../SURFACE-REGISTER.md) naming the row that
  consumes it
- **Gate 5b re-checked.** It has been blocked for five rows waiting for a running entry point, and
  this is where it unblocks. It has never run against anything, so expect it to name dead surface —
  each name is a finding, not something to exempt.
- Ledger rows updated for what actually finished, and not for what nearly did
