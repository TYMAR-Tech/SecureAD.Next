# S-42 - The visual language

Produces: `docs/next/S-42-the-visual-language.md`. Governing records: `0046`, `0045`, `0002`, `0055`,
`0039`.

This is the session [`0046`](../../decisions/0046-the-shell-is-wpf.md) deferred. That record chose
WPF over WinUI 3 knowing the product would look plain until this happened, and says so in as many
words: *"The visual language is unbuilt work, and this record is where that debt is acknowledged."*
It is now four screens' worth of debt and will be twenty screens' worth if it waits.

**Taken ahead of sessions 3, 5 and 6** (parallelism, exclusion and attestation, member
classification) at the owner's decision after seeing `S-41` working. His words: *the foundation is
there; the cosmetics need cleaning up*.

## What this session is actually about

**It is not decoration, and treating it as decoration is how it goes wrong.**

This product's central rule is that a thing the run did not measure must never look like a thing the
run measured and found wanting. Every session so far has enforced that in *sentences* -
`Established`, `PreflightAnswer`, `PdcEmulatorKnowledge`, three states each, with a distinct wording
for the middle one.

A visual language is where that rule is most easily lost, because the ordinary way to style a status
is two colours. Green and red. Tick and cross. A design system with two status treatments applied to
a three-state fact silently deletes the middle state that fourteen months of decisions exist to
protect - and it deletes it in the layer a customer actually looks at.

So the real work here is **giving "not established" a look of its own**: neither the reassuring one
nor the alarming one, visibly a third thing, and legible to someone who cannot distinguish red from
green. The colours, the spacing and the fonts are the easy half.

## Scope

**In.**

- **A design system built by hand**, in resource dictionaries under `SecureAD.Shell`. Colour,
  a type scale, spacing, and control templates for the controls the product actually uses:
  `Button`, `TextBox`, `TextBlock`, `RadioButton`, `DataGrid`, `ScrollViewer`, `Border`.
  No third-party package - `0046` forbids it and that constraint is the owner's, not the
  engineering's.
- **A named brush per audit state, and there are three of them, not two.** Established-and-good,
  established-and-bad, and not-established. Plus a fourth for a fault the run reported. Named for
  what they mean, never for what they look like: a brush called `Warning` survives a palette change
  and a brush called `Orange` does not.
- **Colour is never the only carrier.** An operator who cannot distinguish red from green must be
  able to tell a fault from an unknown from a clean answer. Shape, weight, an outline, a prefix -
  something in addition to hue. This is not a nicety in a tool people make security decisions on.
- **Every hard-coded colour literal removed from the views.** There are currently `DarkRed`,
  `DarkOrange` and `Gray` scattered through `HomeView`, `RunLibraryView` and `NewAuditView`, each
  chosen in isolation. They become named resources.
- **A gate forbidding their return.** A build failure when a colour literal appears in a view
  outside the dictionary, in the shape `SchemaGuidSingleSourceGateTests` already uses for GUIDs.
  With its scanner self-test, per `README.md` § Gates.
- **The New Audit domain rows become a table.** They are currently a stack of label-and-value pairs
  per domain, which is what fitted in one session. The brief for `S-41` asked for a table and the
  facts are table-shaped: one row per domain, one column per fact. `0046` chose WPF partly because
  twenty-one of the predecessor's thirty-six XAML files use `DataGrid`; this is the second place it
  earns that.
- **The window chrome that is still missing** - ledger row `J3` records a rail only, with header and
  status bar owed and explicitly deferred *"to be decided against the visual language"*. This is
  that session. **Whether a status bar exists at all is the owner's call and must be asked, not
  assumed**: a status bar that has nothing true to report is a strip of chrome pretending to be
  telemetry.
- **A decision record, `0056`**, stating what the design system encodes and why the three-state
  treatment is a rule rather than a preference. `0046` is not restated; it is cited.

**Out, deliberately.**

- **Any change to what is said.** This session changes how facts look, never which facts appear or
  in what words. If a sentence on screen turns out to be wrong, that is a finding with a severity,
  not a quiet rewording - and a cosmetic session is exactly where a wording change hides best.
- Parallel preflight and capture, `ServerLimits`, `0040`'s retry (`F-S40-1`). Session 3.
- Exclusion, the per-domain checkbox, the attestation prompt (`F-S40-2`). Session 5.
- Group member classification and the verifier. Session 6.
- Any new screen. Findings, reports and dashboards are `0045`: screens bound to judgement are left
  out rather than stubbed, and a navigation entry leading to an empty screen tells an operator
  something was looked for and nothing found.
- Icon fonts, image assets, animation. If an icon is wanted it is drawn as a path in XAML or it
  waits.
- Dark mode. It doubles every decision in this session before one of them has been seen working.
  **The predecessor has `DarkTheme.xaml` and `LightTheme.xaml` and they are not being ported.** They
  are worth reading for what a palette needs to name; they are not a starting point, and a design
  system built to switch before it has been built to work once is two unfinished designs.

## Where this starts

**`S-41` must be committed and run against the owner's forest before this session begins, and that
is a prerequisite rather than a preference.**

`S-41` is built and its 1,129 tests pass, but **it has never been run against a directory**. The
owner has a live three-domain forest, `ad.lab`, with `ba.ad.lab` and `ph.ad.lab` beneath it, one
domain controller in each, no subnet objects declared, and every controller in
`Default-First-Site-Name`. A full capture takes about fifteen seconds.

Two things must be seen on that forest before any of it is styled:

- **the PDC emulator prompt must not appear on any row** - one controller per domain means there was
  never an alternative, and `0055`'s amendment narrowed the prompt to the domains where an operator
  could have chosen differently;
- **no domain may be described as being in another site** - the forest declares no subnets, so the
  run has no site and has measured nothing about where its controllers are relative to it.

Four of `S-40`'s thirteen findings came from three commands against that lab, and three of those
were defects no test had caught because they concerned what the product *said*. Styling a screen
that is telling a customer something false produces a well-presented falsehood.

**A note on searching this repository:** `git grep` and `git ls-files` do not see untracked files.
The session that opened `S-40` searched for `S-39`'s output, found nothing, and concluded session 1
had never run - it had, and was uncommitted. Check `git status` before concluding anything is absent.

## A decision that is getting more expensive weekly

**`SecureAD.Shell` is not covered by any architecture gate.** `RebuildAssemblies.All` names
`SecureAD.Kernel`, `SecureAD.Evidence` and `SecureAD.Audit`. The surface register (gate 5a), the
concept registry (gate 2) and the vouched-return guard (gate 4) therefore do not see a single shell
type. `ShellMvvmGateTests` is the only thing watching that project, and it is a text scan over file
paths rather than a reflection over the compilation.

Found at `S-41` while adding six public shell types, none of which needed a register entry because
nothing asked for one.

This is the shape of failure gate 5 exists for, and `README.md` § Gates is explicit that it *"cannot
be retrofitted onto a large codebase, which is exactly why the old one carries six unreachable grids
and twenty-eight commands bound to nothing"* - and those grids were in the presentation layer. A
session that adds a resource dictionary, control templates and a table is a session that grows shell
surface substantially.

**Raise it with the owner at the start of the session.** Bringing `SecureAD.Shell` under the gates is
cheap today and expensive at thirty types. It is not obviously in scope here and it is not obviously
deferrable either, which is why it is a question rather than a task.

## What remains after this session

Three sessions from `S-38` § 7 remain, and the documentation carrying them is behind - `WHAT-THE-OLD-APP-HAD`
still shows `A3`, `A4` and `A5` as not started although `S-39` closed them. **That is known and is
the owner's to fix after this arc, not before.**

| Session | Work | Carries |
|---|---|---|
| 3 | Parallel preflight and capture, the fan-out guard, `ServerLimits` | `F-S40-1` - `0040`'s retry, which nothing walks today |
| 5 | Exclusion and attestation: the per-domain checkbox, the attestation prompt, coverage identity | `F-S40-2` - a domain with no candidates currently stops a capture as a placeholder |
| 6 | Group member classification and the verifier | The `ResolveParentGuids` fix, ledger row `B11` |

`S-41` also left four findings open, and two of them are shell-shaped enough to be worth reading
before touching this code: `F-S41-3` (the two read-only seam calls still create the run library
folder) and `F-S41-4` (each Validate press costs a full discovery pass).

Beyond those, the ledger is the map, and most of the read-and-display half of the product
(`C16` to `C23`) is still undecided rather than merely unbuilt.

## Read first

- `docs/decisions/0046-the-shell-is-wpf.md` - the whole of it, and § Consequences twice. The
  no-third-party constraint, the single-executable requirement, and the deferral this session
  discharges.
- `docs/next/S-41-the-new-audit-wizard.md` - what the New Audit window shows and why each fact is
  the type it is. § *Three states, because a window is otherwise a two-state control* is the part
  this session must not undo.
- `docs/next/S-40-wiring-discovery-into-capture.md` - findings `F-S40-8`, `F-S40-10` and `F-S40-11`.
  Three instances of one mistake: an unasked question rendered as a negative answer.
- `docs/decisions/0002-absent-view-means-degraded-run.md` - the record all of that descends from.
- `docs/decisions/0045-the-shell-is-built-before-the-judgement-half.md` - why there are three screens
  and not nine.
- `docs/next/S-35-a-shell-you-can-click.md` - what the plain shell was, and what it deliberately left
  for this session.
- `docs/next/README.md` § `Tests`, § `Gates`, § `When a document counts as documentation`.
- The current views, all four, end to end: `ShellWindow.xaml`, `HomeView.xaml`,
  `RunLibraryView.xaml`, `NewAuditView.xaml`. They are 350 lines in total.
- `next/tests/SecureAD.Next.Tests/Architecture/ShellMvvmGateTests.cs` - the guards already on this
  project, and their forbidden-term lists.
- **The old application, as the thing being replaced rather than a model:**
  `src/SecureAD.UI/Themes/` - `DarkTheme.xaml`, `LightTheme.xaml`, `Icons.xaml`,
  `InspectorStyles.xaml` - and any grid under `src/SecureAD.UI/Views/`, of which there are
  twenty-nine files. Worth twenty minutes to see what was there and what a palette had to name. Not
  worth copying: the map records six of those grids as unreachable by any user.

## Rules

- § `Tests` and § `Gates` of `docs/next/README.md` bind this session, including the scanner self-test
  every gate carries.
- **A two-state visual treatment may not be applied to a three-state fact.** This is the session's
  standing rule and it is the reason the session is not trivial. Not established, established-and-no,
  and established-and-yes get three distinct treatments, or the control is wrong.
- **Colour is never the only difference between two meanings.**
- **No third-party package.** `0046`. Microsoft-published only, and the product already has its one:
  `CommunityToolkit.Mvvm`.
- **No wording changes.** A sentence that is wrong is a finding. A sentence that is ugly is also a
  finding. Neither is an edit made in passing during a styling session.
- **View code-behind stays empty** beyond `InitializeComponent`, and services are constructed only in
  `App.xaml.cs`. Both are enforced by `ShellMvvmGateTests` and both exist because the predecessor
  accumulated logic where it could not be tested and could not be found.
- **A view model may not gain a `Brush`, a `Color`, a `Visibility` or a `Style`.** A view model that
  decides what something looks like has moved presentation into the one layer that has tests.
  `Visibility` is already on the forbidden list; add the rest.
- **The single executable must still publish.** `--self-contained -p:PublishSingleFile=true
  -p:IncludeNativeLibrariesForSelfExtract=true`, one `SecureAD.exe`, nothing beside it. `0046`
  records that this is an operational requirement rather than an optimisation. **Do not run the
  publish on the owner's machine without asking**, and say where the output went if you do.
- New public types in `SecureAD.Audit`, `SecureAD.Kernel` or `SecureAD.Evidence` need a
  `SURFACE-REGISTER.md` entry. New types in `SecureAD.Shell` currently need none - see the section
  above, and do not treat that silence as permission.
- Do not reintroduce scoped capture, an OU picker, or an object-class picker. `0052`.
- Deletions are part of this session: every colour literal in a view, and any spacing or font size
  chosen ad hoc that a scale now covers.

## Finish by

- The solution builds and the whole `SecureAD.Next.sln` suite passes.
- The window runs, and the owner has seen all three screens and said whether they are right. **This
  is the only acceptance test this session has that matters**, and it cannot be automated: tests
  catch drift and omission, a person catches ugly.
- A gate test fails the build when a colour literal appears in a view, carrying its scanner
  self-test, mutation-tested in both directions with the directions recorded.
- The three-state treatment is demonstrated to the owner on a real screen - the New Audit table
  against `ad.lab`, where every domain is chosen without full knowledge and nothing has been asked
  before the Review step. If the middle state is not obviously a third thing when he looks at it,
  it is not done.
- `0056` is written, stating what the design system encodes, the three-state rule, and the
  colour-is-not-alone rule. `0046`'s deferral paragraph is amended to point at it.
- Ledger rows `J3` and `J19` are decided and updated. `J19` is *Theme, converter and behaviour
  layer* and is currently `(undecided)` in every column.
- `docs/next/S-42-the-visual-language.md` is written, including what the design system deliberately
  does not do.
- Any disagreement found between a document and the code is recorded as a finding rather than
  quietly repaired.
