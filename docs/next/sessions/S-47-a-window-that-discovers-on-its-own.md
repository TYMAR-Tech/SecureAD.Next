# S-47 — A window that discovers on its own, and a preflight that asks several domains at once

Produces: parallel preflight, automatic discovery when the New Audit window opens, a Validate that
contacts one machine, a slice document describing the pass, and the capabilities added to
[`docs/areas/the-new-audit-wizard.md`](../../areas/the-new-audit-wizard.md).

Governing records: [`0048`](../../decisions/0048-preflight-proves-a-controller-before-a-run-commits.md)
(**amended by this session**), [`0055`](../../decisions/0055-the-pdc-emulator-is-established-at-preflight.md),
[`0056`](../../decisions/0056-the-visual-language-encodes-three-states.md),
[`0050`](../../decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md),
[`0053`](../../decisions/0053-the-tool-finds-its-own-forest.md),
[`0002`](../../decisions/0002-absent-view-means-degraded-run.md).

## Where the tree is

`S-46` is written and **has not been run**. This session was taken ahead of it at the owner's
direction: the wizard's behaviour on opening is what he wanted changed first, and the exclusion
attestation `S-46` covers is easier to judge against a window that fills itself in.

**Three of this session's thirteen steps are already committed.** They changed no behaviour:

- `ControllerSelectionTests` gained `TwoDomainsAreNeverPinnedToTheSameController` and its negative
  control `AControllerDeclaringTwoDomainsIsPinnedForBoth`.
- `SerializedDirectoryAccessGateTests` was widened — see below.
- `Preflight.cs` was split, with the per-domain reading moved to `DomainPreflightRead.cs`.

## What the previous session found, and must not be re-derived

**The gate was watching the wrong vocabulary.** `SerializedDirectoryAccessGateTests` matched only
raw `System.DirectoryServices.Protocols` type names. Everything written since the rebuild speaks
through the product's own `IDirectoryChannel`, so `Preflight.cs`, `ForestDiscovery.cs`,
`ForestRoles.cs` and `CaptureSession.cs` matched nothing and were unguarded. A `Task.WhenAll` added
to preflight would have passed. The pattern now covers both vocabularies, the self-test asserts the
new patterns match, and it looks `Preflight.cs` up by name so the blindness cannot return quietly.
**Mutation-tested both directions before being trusted.**

**Domain disjointness is a property of Active Directory, not of this code.** A domain's candidates
are controllers whose `msDS-hasMasterNCs` names it, and a controller holds one domain — so two
domains never share a pinned controller in any real forest, which is what makes parallel preflight
safe. But `ControllerSelection` has no rule against it, and pins the same host twice when handed a
forest that declares one. **The dispatcher must group domains by pinned controller** and run only
distinct controllers concurrently. Relying on the disjointness is the defect this warns about.

## What the owner decided, so the session does not re-open it

- **Preflight runs in parallel.** This overrides `0048`'s *"Preflight is sequential… this is slower
  than the predecessor on purpose"*. The **same-controller rule is untouched** and the amendment
  must say so loudly, or a later reader takes "we made it parallel" as licence to pipeline one
  server.
- **Opening the New Audit window runs both passes automatically** — discovery and the per-domain
  check — and lands on the **Domains** step, not Review. Start stays behind the Review step, so
  opening the window is never one click from a multi-hour capture.
- **The indicator is indeterminate.** A static "Discovering forest…" that clears when everything has
  returned. Not a real progress bar, so the audit layer keeps returning one result at the end and no
  per-domain reporting seam is needed.
- **Validate contacts one machine and nothing else.** It stops calling `PlanAsync`. It proves the
  typed host by asking the host what partition it serves — the predecessor's
  `ForestDcPreflightService` shape — rather than by consulting the forest's candidate list.
- **A refused override raises a dialog** naming the rejected host, and **clears the box** on
  dismissal so the row falls back to the ranked choice. An operator is never trapped in a refusal he
  cannot dismiss.
- **Site stays *not established*** for a typed host the forest does not name. That is `0056` working,
  and it is a useful signal in itself: *answers, serves the right partition, forest does not list it.*

## Questions only the owner can answer

1. **Whether the indicator needs a Cancel.** Opening the window is now a network act against every
   domain, with no way out while it runs. Build it, watch it, then decide.
2. **What the window shows when the forest cannot be reached on open.** There is no button left to
   press, so an empty table with no reason given is the failure mode to avoid.

## Scope

**In.**

1. **The PDC re-pin reworked to hold no shared state.** Today it rewrites `roles`, `selection` and
   `units[i]` mid-loop and re-asks the domain against a new controller. Two domains doing that at
   once produce a plan reflecting neither. This is the delicate part of the session.
2. **Concurrency in the dispatcher**, grouped by pinned controller, with the report order stable.
3. **`0048` amended.**
4. **The single-host check**, and `ValidateOverrideAsync` rewritten onto it.
5. **The refusal dialog**, behind `INewAuditDialog` so the view model stays testable.
6. **Automatic discovery on open**, the two buttons removed, the indicator added.
7. **A slice document**, and the area file updated: every new capability naming the test that proves
   it, `F-S41-4` closed, and the *worked out on opening or on a press* question moved out of
   *What has not been discussed*.

**Out, deliberately.**

- **The exclusion attestation and the tick box** — that is `S-46`, and the owner has agreed it comes
  after this.
- **Trimming the table.** Ten columns against the predecessor's seven. Agreed to be reviewed last,
  once there is a filled table to judge.
- **Where a running capture reports itself.** `0060` decides the content, not the placement.

## Rules

- **Nothing on screen states a fact the run did not measure.** The standing rule of this area.
- **Three states, never two.** `0056`. A boolean anywhere in this work is a defect.
- **No guard is weakened to let a change pass.** If the split cannot satisfy
  `SerializedDirectoryAccessGateTests` on its current wording, that is a finding and a conversation.
- **Every new guard is mutation-tested in both directions**, and the directions observed are
  recorded.
- **Every capability added to the area file names the test that proves it.** `AreaFileGateTests`
  fails the build otherwise.
- **No golden value or frozen fixture is edited.** One that needs changing is a finding.

## A note on searching this repository

`git grep` and `git ls-files` are the only searches to trust here; the built-in file search returns
empty results for tracked files under `docs/`.
