# S-41 - The New Audit wizard

> **This records session S-41 as of 2026-08-11. Nothing here states current behaviour.**  
> It is kept for the reasoning it carries, not as documentation. See [`docs/history/README.md`](README.md).

**Status: built and tested; not yet run against a forest.** Everything below is proven by the test
suite. Nothing below has been seen working against the owner's lab, and that is the one thing this
session owes - see [Owed](#owed).

This document is discussion, not authority. Where it disagrees with the code, the code wins, and the
disagreement is a finding.

**Governing records:** [`0025`](../decisions/0025-the-run-library-is-a-managed-root.md),
[`0039`](../decisions/0039-one-way-to-start-a-capture.md),
[`0045`](../decisions/0045-the-shell-is-built-before-the-judgement-half.md),
[`0046`](../decisions/0046-the-shell-is-wpf.md),
[`0047`](../decisions/0047-settings-are-per-user-and-per-machine.md),
[`0048`](../decisions/0048-preflight-proves-a-controller-before-a-run-commits.md),
[`0052`](../decisions/0052-the-domain-is-the-only-unit-of-scope.md),
[`0053`](../decisions/0053-the-tool-finds-its-own-forest.md),
[`0055`](../decisions/0055-the-pdc-emulator-is-established-at-preflight.md).

Ledger row: `J11`.

---

## What this replaces

The Home screen carried a text box labelled "Domain controller", a Run button that stayed disabled
until something was typed into it, and a line of help text telling the operator to name one. All
three are deleted.

They asked for the single thing the product can work out for itself. `0053` settled that the run
finds the forest this machine is in, and `S-40` built it - so the old screen made the recovery path
for an unjoined machine into the ordinary path for everybody else. It also offered nowhere to see
what a run would do before it did it: an operator pressed Run and found out three hours later.

`HomeViewModel` keeps one job, which is choosing the run library `0025` refuses to guess at.

---

## What was built

### The seam widened rather than a second one appearing - `ICaptureLauncher`

`0039` allows a window to be a caller of the one capture entry point and nothing else. The seam now
has three calls where it had one:

| Call | What it does | What it contacts |
|---|---|---|
| `PlanAsync` | Works out what a run would read and from where | One connection, for the configuration partition |
| `ValidateAsync` | Asks every domain the four preflight questions | One connection per domain |
| `RunAsync` | Reads the forest into a sealed bundle | The capture itself |

Each maps straight onto `CaptureSession.PlanAsync`, `ValidateAsync` and `RunAsync`. `CaptureLauncher`
ranks nothing, decides nothing and opens nothing of its own.

**No audit type crosses the seam.** A view model that can see a `CaptureSession` can start one, and
the point of the seam is that it cannot. What crosses is `AuditPlanView`, `AuditCheck` and
`DomainPlanRow` - the same facts in a shape a window can render without knowing what a naming
context is.

### Three states, because a window is otherwise a two-state control - `Established`

This is the whole of the session's standing rule and it is a type rather than a convention.

`F-S40-8`, `F-S40-10` and `F-S40-11` were one mistake made three times: a question the run never
asked, rendered as a negative answer. A console can be careful about that sentence by sentence. A
table cannot - every cell has to hold something, and the honest thing to hold is usually the thing
nobody thinks to write.

So every fact that can be unknown is `Established` - `NotEstablished`, `Yes`, `No` - and every fact
that cannot is a boolean:

| Fact | Type | Why |
|---|---|---|
| Serves the partition | `Established` | A controller nothing answered from was never asked |
| Password Settings Container readable | `Established` | Same |
| Is this domain's PDC emulator | `Established` | `0055` forbids "not established" rendering as "holds no role" |
| A rung answered | `Established` | Nothing answered is not a refusal to protect |
| Controller is in this machine's site | `Established` | A run with no site has measured nothing about where a controller is |
| Choice was fully informed | `bool` | The run either had every input to the ranking or it did not |
| Controller was named by the operator | `bool` | A human either insisted or did not |
| Read from the PDC emulator | `bool` | Meaningful only once the emulator was established, and false where it was not |

`SiteKnowledge` is the same rule applied one level up: a forest that declares no subnets and a
machine whose address is in none of the subnets a forest does declare are different faults with
different remedies, and one sentence covering both sends an operator to the wrong place.

### Two steps, held as a list

`Steps` is `[Domains, Review]` - data rather than a chain of conditions, so a third and a fourth
arrive by being added to it. The predecessor had five. Two of its steps chose an organisational unit
and an object class, which `0052` removed; the third set a per-controller load limit, which is
session 3.

**Start is the only commitment and there is no prompt behind it.** The Review step is the
confirmation. An operator who has read the table and the warnings has confirmed, and a dialog asking
whether he meant it is the kind of thing people learn to dismiss.

### The override - refused, never softened

An operator types a controller for a domain and presses Validate. The whole plan is worked out
again, because eligibility is a property of the forest's candidate list for that domain and no such
list crosses the seam. If `ControllerSelection` refuses the name, the row shows the library's own
words, unedited, and `CanStart` goes false.

Nothing here downgrades that to a warning, retries it, or falls back to the ranked choice. The
predecessor fell back silently, so an operator who mistyped a host name got a successful run against
a controller he did not name.

The override is per run and never stored, per `0047`. It lives in the row's text box and nowhere
else.

### The PDC emulator prompt, narrowed - and `0055` amended to say so

`0055` said the run proceeds against a PDC emulator and *says so*. That was written with a console in
mind. In a window it produces a warning on every row of the owner's own lab - three domains, one
controller each - every time, with nothing the operator can do about any of them.

The prompt now appears only where the forest names another controller for the domain, which is
exactly where the operator could have chosen differently.

**The record did not narrow.** `preflight.json` carries `ReadFromPdcEmulator` for every domain it is
true of. The record is for whoever reads the bundle six months later and asks why a capture took
nine hours; the prompt is a question put to somebody standing there who can act. Only the second is
conditional.

`0055` carries an amendment saying this, dated, rather than the rule living here.

---

## Proven

Each of these was mutation-tested: the guard was broken, the failure was watched, the break was
reverted.

| Obligation | Test | Break that was watched to fail |
|---|---|---|
| An ineligible override refuses the run from the window | `AnIneligibleControllerIsRefusedInTheLibrarysOwnWords`, `AnIneligibleControllerStopsTheRunFromStarting`, `AnIneligibleControllerIsNotQuietlyReplacedByTheRankedChoice` | Clearing the row's problem and leaving `RunMayProceed` alone on a refusal |
| The prompt appears with alternatives and not without | `ThePdcEmulatorPromptAppearsWhereTheDomainHasAlternatives`, `ThePdcEmulatorPromptDoesNotAppearWhereTheDomainHasNoAlternatives` | Dropping `&& Alternatives.Count > 0` |
| `preflight.json` records `ReadFromPdcEmulator` either way | `ThePreflightFileRecordsThatADomainWasReadFromItsPdcEmulator` | Predates this session; see `F-S41-1` |
| An unestablished fact renders as unknown, not as false | `APdcEmulatorThatCouldNotBeEstablishedIsNotReportedAsHoldingNoRole`, `AQuestionNotYetPutIsShownAsNotYetPutRatherThanAsNo`, `ThePdcEmulatorIsNotReportedAsAbsentBeforeItIsEstablished`, `AControllerIsNotReportedAsElsewhereByARunWithNoSite`, `AControllerNothingAnsweredFromIsNotReportedAsRefusingProtection` | Folding `NotEstablished` into the negative answer; removing the `WasPreflighted` guard |

The whole `SecureAD.Next.sln` suite passes.

---

## Not built

- **Exclusion, the per-domain checkbox and the attestation prompt.** Session 5. The table is
  read-only apart from the controller, and a domain the forest names no controller for stops the run
  rather than being excluded - which is what `CaptureSession` already does.
- **Parallel preflight and capture, `ServerLimits`, any per-controller load setting.** Session 3.
- **Progress beyond "running".** The capture layer has no per-object count to report and inventing
  one on screen would be a picture of a run rather than a report of it. A progress reader is wanted
  and needs something honest to read first.
- **Any styling.** The window is deliberately unstyled, like the rest of the shell.

---

## Findings

### `F-S41-1` - the `preflight.json` obligation was already met - **resolved**

The brief asked for a test that fails if `preflight.json` stops carrying `ReadFromPdcEmulator` for a
single-controller domain. `DiscoveryWiringTests.ThePreflightFileRecordsThatADomainWasReadFromItsPdcEmulator`
already did exactly that, written at `S-40`, against a forest of one controller.

No new test was written. The existing one gained an assertion that the domain has no alternatives at
all, so the fixture cannot drift onto a multi-controller domain and keep passing while the case that
matters goes unwatched - which is the case whose *prompt* this session suppressed. Its remarks now
say why that shape is the point rather than an accident.

Recording it rather than quietly reusing the test, because "the obligation was already met" and "the
obligation was met by accident and is one fixture edit from not being" are different states.

### `F-S41-2` - preflight's answers arrive with no site information - **open, by design**

`PreflightReport` carries a `CapturePlan`, which has no topology and no operator site. So preflight
can say which controller answered and what it answered, and nothing about where that controller is.

The window therefore merges preflight's answers onto the rows discovery produced, rather than
rendering preflight's output directly. Where `0055`'s re-pin moved a domain to a different
controller, the row looks that controller's site up again in the topology discovery already read -
it does not carry the previous controller's site across, which would put a measured-looking site
beside a machine nobody measured.

The alternative was a second discovery pass inside `ValidateAsync`, which would be two answers to
one question and would eventually disagree. Left as it is. If a later session gives `PreflightReport`
the `ForestPlan` rather than the `CapturePlan`, this merge should go.

### `F-S41-3` - the two read-only calls still take a run library, and it gets created - **open**

`PlanAsync` and `ValidateAsync` write nothing, but they are still given the operator's library root,
because a `CaptureSession` is constructed over a `RunLibrary` and `RunLibrary`'s constructor calls
`Directory.CreateDirectory` on its root.

So pressing "Work out what would be read" creates the library folder if it is not there. No run is
created inside it. The CLI's `--preview` avoids this by building no session at all, and this surface
cannot, because `ValidateAsync` lives only on the session.

It is small and it is a difference between two surfaces that are supposed to behave alike. Worth
either moving `ValidateAsync` off the session or making `RunLibrary` create its root lazily.

### `F-S41-4` - Validate costs a discovery round trip per press - **open**

Checking one typed controller re-plans the entire forest. Eligibility is a property of the forest's
candidate list for that domain, and no candidate list crosses the seam - so there is nothing on this
side to check a name against.

On a lab that is a second. On a large forest an operator correcting three host names pays three full
discovery passes. The fix is to carry the eligible candidates per domain across the seam, which
`ForestPlan` already holds, and check locally before spending a round trip. Not done here because a
local check that disagreed with the library's would be worse than a slow one.

### `F-S41-5` - `ShellSection` gained a member for a screen that can answer for itself - **resolved**

`ShellSection`'s remarks say a member is added only when the screen behind it can answer for itself,
and that navigation entries leading to empty screens are what the predecessor accumulated. `NewAudit`
qualifies: it plans, checks and starts a real run.

Recorded because the rule is easy to erode one screen at a time, and the next session that wants a
navigation entry should have to make the same argument.

---

## What the brief got wrong

**"`PlanPreview` and `PreflightReport` already carry every one of these; nothing new is computed."**
True of the four preflight answers and the failover list. Not true of the site columns, which
`PreflightReport` does not carry at all - see `F-S41-2`. Nothing new is *computed*; something new had
to be *merged*.

**"The `reportPreflight` seam added at `S-40` is what fills the table."** It is not. That seam fires
during a run, after the operator has pressed Start, which is too late to be a table he reads before
deciding. The table is filled by `ValidateAsync`, which is the same preflight pass performed on its
own - which is what `S-40` built it for. `reportPreflight` is passed as null from this surface,
because everything it would say has already been said on the Review step.

---

## Owed

**This has not been run against a forest.** The owner's three-domain lab is where the interesting
cases live and both of them are always present there: one controller per domain, so the PDC prompt
must be absent, and no subnets declared, so every domain must report as chosen without full
knowledge and no controller may be described as being in another site.

Four of `S-40`'s thirteen findings came from three commands against that lab, and three of them were
defects no test had caught because they were about what the product *said*. This session is more
exposed to that class of mistake than `S-40` was, not less.

Ask for a run before treating any of this as finished.
