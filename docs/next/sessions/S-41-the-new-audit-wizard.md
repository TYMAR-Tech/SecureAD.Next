# S-41 - The New Audit wizard

Produces: `docs/next/S-41-the-new-audit-wizard.md`. Governing records: `0039`, `0046`, `0047`,
`0048`, `0053`, `0055`, `0025`, `0052`.

This is session 4 of the six planned in `S-38` § 7, taken ahead of session 3 because the shell is
what the owner wants next and parallelism buys nothing until a forest is larger than a lab.

**Approved by the owner 2026-08-11**, including the two-step stepper, the override with a Validate
action inside an otherwise read-only table, the narrowed PDC prompt with an unconditional record,
and the standing rule under §`Rules` that nothing on screen may state a fact the run did not
measure.

## Scope

**In.** The first point at which any of the last two sessions is visible.

- **New Audit becomes a window**, replacing the current Home screen's controller text box and Run
  button. It finds the forest by itself per `0053` and asks for nothing it can work out.
- **A stepper with two steps: Domains, then Review.** The old app had five; three of them
  (`CaptureContent`, `CaptureLoad`, `GppScan`) have no home here - `0052` removed scoped capture,
  and per-DC load limits are session 3. The shape must take a third and fourth step later without
  being rebuilt.
- **A read-only domain table.** Per domain: the naming context, the controller it would be read
  from, that controller's site, the ranked failover list, whether the choice was fully informed,
  and after preflight the four answers and the PDC emulator state. `PlanPreview` and
  `PreflightReport` already carry every one of these; nothing new is computed.
- **A manual controller override per domain, with a Validate action.** The operator types a
  controller name and validates it before committing the run. An ineligible name is refused in the
  window exactly as it is at the command line - `ControllerSelection` already refuses it and the
  window must not soften it into a warning. Per run, never stored, per `0047`.
- **The PDC emulator warning, narrowed.** It appears only where the domain has other controllers -
  that is, where the operator could have done something about it. A warning that fires on every
  domain of a single-controller forest trains an operator to click past warnings.
  **`preflight.json` still records it either way**: the record is a fact about the audit, and only
  the prompting is conditional.
- **An amendment to `0055`** stating that, because it narrows "and says so".
- **The run started from the window is the same run.** `CaptureSession` is called, not
  reimplemented, per `0039`. The `reportPreflight` seam added at `S-40` is what fills the table.
- **Start begins the capture.** The Review step is the confirmation; there is no second prompt
  behind the button. An operator who has read the table and the warnings has confirmed, and a
  dialog asking whether he meant it is the kind of thing people learn to dismiss.

**Out, deliberately.**

- Exclusion, the per-domain checkbox and the attestation prompt. Session 5. The table is read-only
  this session; leave room for a column and a per-row action without designing them.
- Parallel preflight and capture, the fan-out guard, `ServerLimits`, any per-DC load setting.
  Session 3.
- `0040`'s retry (`F-S40-1`). Session 3.
- Group member classification and the verifier. Session 6.
- Progress detail beyond what the capture layer already offers. It has no per-object count and
  inventing one on screen is a picture of a run rather than a report of it. **A progress reader is
  wanted and is a later session**: it needs something to read, and giving the capture layer
  something honest to report is its own piece of work rather than a label on this one.

## Where this starts

The tree is clean at `ae0fcc96`. `S-39` and `S-40` are committed and the whole
`SecureAD.Next.sln` suite passes - 1111 tests at the time of writing.

**`S-40` was not only built, it was run.** The owner has a live three-domain forest, `ad.lab`, with
`ba.ad.lab` and `ph.ad.lab` beneath it, one domain controller in each, no subnet objects declared
and every controller in `Default-First-Site-Name`. A full capture of it takes about fifteen seconds
and produces a sealed bundle. He is willing to run builds against it and paste the output.

**Use that.** Four of `S-40`'s thirteen findings came from three commands against that lab, and
three of them were defects no test had caught because they were about what the product *said* rather
than what it computed. A window is more exposed to that class of mistake than a command line is, not
less. Ask him to run it before declaring anything finished.

Two properties of that forest matter for this session: with one controller per domain the PDC prompt
must **not** appear under the rule below, and with no subnets the run has no site, so every domain
reports as chosen without full knowledge. Both are the interesting cases and both are always
present there.

**A note on searching this repository:** `git grep` and `git ls-files` do not see untracked files.
`S-38` § 9 carries the same warning and it was not read early enough - the session that opened `S-40`
searched for `S-39`'s output, found nothing, and concluded session 1 had never run. It had; it was
uncommitted. Check `git status` before concluding anything is absent.

## What remains after this session

The documentation that ought to carry this is behind - `WHAT-THE-OLD-APP-HAD.md` still shows `A3`, `A4` and
`A5` as not started when `S-39` closed them, and the unrun-prompts table in
[`README.md`](README.md) has not been kept up. **That is known and is the owner's to fix after this
arc is finished, not before.** The table below is here so the remaining work survives in the
meantime.

Three sessions remain after this one, from `S-38` § 7:

| Session | Work | Carries |
|---|---|---|
| 3 | Parallel preflight and capture, the fan-out guard, `ServerLimits` | `F-S40-1` - `0040`'s retry, which nothing walks today |
| 5 | Exclusion and attestation: the per-domain checkbox, the attestation prompt, coverage identity | `F-S40-2` - a domain with no candidates currently stops a capture as a placeholder |
| 6 | Group member classification and the verifier | The `ResolveParentGuids` fix, ledger row `B11` |

Session 3 was deferred past this one deliberately: parallelism buys nothing until a forest is larger
than a lab, and the owner wanted the shell first.

Beyond those three the ledger is the map, and most of the read-and-display half of the product
(`C16` to `C23`) is still undecided rather than merely unbuilt.

## Read first

- `docs/next/S-40-wiring-discovery-into-capture.md` - what exists, what is proven, and findings
  `F-S40-1` to `F-S40-13`. `F-S40-8`, `F-S40-10` and `F-S40-11` are three instances of one mistake
  and are the thing most likely to be repeated by a screen.
- `docs/next/sessions/S-38-the-new-audit.md` §§ 2, 6, 7.
- `docs/decisions/0039-one-way-to-start-a-capture.md` - a graphical surface is a caller, never a
  second implementation.
- `0046` (the shell is WPF), `0045` (the shell is built before the judgement half).
- `0047` (an override is per-run and never stored), `0048` (preflight's four questions),
  `0053` (the tool finds its own forest), `0055` (the PDC emulator is established at preflight),
  `0025` (the run library is a managed root), `0052` (the domain is the only unit of scope).
- **The old application, as the idea rather than the specification:**
  `src/SecureAD.UI/ForestAuditWindow.xaml`,
  `src/SecureAD.UI/ViewModels/ForestAuditViewModel.Wizard.cs` (the step sequence and per-step
  validation), `src/SecureAD.UI/ViewModels/ForestDomainRow.cs` (the row: override input, effective
  DC, per-row preflight status).
- `docs/next/README.md` §`Tests`, §`Gates`, §`When a document counts as documentation`.
- `docs/next/SURFACE-REGISTER.md`.

## Rules

- §`Tests` and §`Gates` of `docs/next/README.md` bind this session, including the scanner self-test
  every gate carries.
- **Nothing on screen may state a fact the run did not measure.** This is the session's standing
  rule and it is why `F-S40-8`, `F-S40-10` and `F-S40-11` are named above: each rendered "unknown"
  as a negative. Any site, PDC, completeness or reachability shown in the table must distinguish
  *not established* from *established and false*. A two-state control over a three-state fact is
  the defect, not the styling.
- The window calls `CaptureSession`. It builds no channel factory, opens no connection of its own,
  and issues no search request. `0039`.
- An override the library refuses must stop the run from the window too, with the library's own
  words. It must not be downgraded, retried, or replaced by the ranked choice.
- Suppressing the PDC prompt must not suppress the record. A test must fail if `preflight.json`
  stops carrying `ReadFromPdcEmulator` for a single-controller domain.
- No new search request outside `CaptureSearchRequestFactory`.
- New public types need a `SURFACE-REGISTER.md` entry naming the row expected to consume them.
- Do not reintroduce scoped capture, an OU picker, or an object-class picker. `0052`.
- Deletions are part of this session: the Home screen's controller text box, its label, and any
  wording that tells an operator to name a controller to start.

## Finish by

- The solution builds and the affected test projects pass.
- The wizard is reachable, and a capture started from it produces a sealed bundle against a real
  forest.
- Each of these has a test proven to fail in both directions:
  - an ineligible override refuses the run from the window;
  - the PDC prompt appears where the domain has alternatives and not where it has none;
  - `preflight.json` records `ReadFromPdcEmulator` regardless of whether the prompt appeared;
  - a fact the run did not establish renders as unknown rather than as false.
- `0055` is amended, or a new record supersedes it, stating the narrowed prompting rule and that the
  record is unconditional.
- `docs/next/S-41-the-new-audit-wizard.md` is written.
- Any disagreement found between a document and the code is recorded as a finding rather than
  quietly repaired.
