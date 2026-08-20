# S-28 — The entry point

## Scope

Build **A9**, the composition root: the one way to start a capture. It is the last piece between a
product that runs in a test and one you can invoke against a real forest.

It should be small — roughly fifty lines — because everything it needs exists. If it is growing,
something is being decided in it that belongs somewhere else.

## What it composes

| Piece | Where |
|---|---|
| `RunLibrary` | resolves the configured root into a fresh run directory |
| `LdapDirectoryChannelFactory` | opens the connection |
| `ForestDiscovery.PlanAsync` | reads the RootDSE, returns a `CapturePlan` |
| `CaptureRun.RunAsync` | walks the plan, writes and seals the bundle |

## What governs it

- [`0039`](../../decisions/0039-one-way-to-start-a-capture.md) — one entry point, taking the run
  directory it is given, completing unattended. A window is a caller, not a second implementation.
  Whether the executable is a console app is packaging and is deliberately left open.
- [`0025`](../../decisions/0025-the-run-library-is-a-managed-root.md) — the root is configuration
  and the operator supplies it. **There is no default and must not be one.**
- [`0018`](../../decisions/0018-connection-security-is-an-ordered-ladder.md) — no prompt at the
  moment of failure, and the unprotected-connection allowance is per run and never remembered.

## Then: a real capture

This is the point of the row. Nothing in this product has bound to a domain controller, completed a
TLS handshake, or seen a real paging cookie. Five observations are owed and are recorded against
**B20**: the wire spelling of a ranged attribute name (`F-S7-37`), whether a controller tolerates a
base-scope search between two pages (`F-S7-39`), what a client sees when a paging bookmark is
evicted (`F-S7-40`), the credential child-object measurement (`F-S7-26`), and a controller declining
a rung.

**Expect the first real run to fail somewhere interesting.** That is what it is for.

## Known-provisional, and not this session's job

`ForestDiscovery` treats every published naming context that is not configuration or schema as a
domain, so it over-reads application partitions. The authoritative answer is the `crossRef`
`systemFlags` in the Partitions container. Recorded on **A7**; finish it after a real capture shows
whether it matters.

## Out of scope

The read side (`D`, `E`), the run library catalogue (`F12`–`F16`), and the architecture-test and
duplicate-sentence work — the owner is taking those after a real capture.

## Rules that still bite

- Decisions are stated once, in `docs/decisions/`. Rows and comments cite; they do not paraphrase.
- A documentation check earns a place only if a change to the **product** can break it.
- Mutation-test any new guard in both directions and say which were observed.
- Long PowerShell goes in a script file under `$env:TEMP`, invoked with a short command.

## Finish by

- `A9` built, with a run reaching a real controller
- Whatever the real capture broke, recorded against the row that owns it
- Gate 5b re-checked: it has been blocked for four rows and this is where it unblocks
- Ledger rows updated for what actually finished — and not for what nearly did
