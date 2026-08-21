# How the app looks

**Area.** The visual language of the window: colour, type, spacing, the controls the product uses,
and — the part that is not decoration — how a fact the run *did not measure* is made to look
different from one it measured and found wanting.

This file is the starting point for any work in this area. **Almost nothing here is decided.** That
is the honest state, not an omission.

---

## How to work in this area

**Read this before changing anything visual.** Two sessions in August 2026 spent most of their
length relearning what is written here. None of it is obvious, and none of it is caught by the
build.

**1. Nothing in this repository can tell you a screen is wrong.** The build went green and 1232
tests passed against a table header rendering dark text on a dark background, four state marks that
all drew the same symbol, and a Stop button offered while nothing was running. XAML has no compiler
check for any of it. **The only instrument is a person looking at a running window**, so plan the
work around that instrument being expensive rather than around it not existing.

**2. Use the gallery, not the screens.** `next/tools/SecureAD.Gallery` is a separate throwaway
program showing every control the design system dresses, once, on one page. One screenshot of it
reports the state of everything. Fixing controls one screen at a time is what made the first two
sessions slow. It is deleted when the styling work is finished.

**3. The product is built on one machine and run on another.** A screenshot is evidence of *nothing*
until it says which build it shows. `ShellWindow.xaml` carries a hand-bumped **build marker** in the
rail for exactly this reason. Four rounds went into a rail that was never broken: the fix worked
immediately and the lab was running a stale copy. Bump the marker with every change, and if a
screenshot does not show the expected marker, conclude nothing from it.

**4. Set a colour on the thing that DRAWS the text, never on the thing that holds it.** A
`ContentPresenter` may or may not pass an inherited value down to whatever it builds, and reading
the XAML will not tell you which. A local value on a `TextBlock` always arrives. This cost three
rounds on one table header. `Controls.xaml` states the rule again at the point it matters.

**5. A value must be in the form the trigger compares.** The four state marks were set with the
*text* `"EstablishedBad"` where the triggers switch on the `FactState` **type**. Nothing matched, so
every mark fell through to the default — the hollow ring, which means *not established*. The product
told an operator a known-bad fact was unknown. **This is the failure class that matters most**: not
ugly, but false.

**6. After two failed attempts, stop reasoning and run an experiment.** Three rounds were spent
theorising about why a colour would not apply. The question was settled in one round by setting the
brush to bright magenta and looking. Prove the style *reaches* the element before arguing about
which colour it should be.

**7. Before concluding a fix failed, prove it was in what ran.** Check the edit is on disk, and that
the executable is newer than the edit. Both checks are one command and both have mattered.

**8. Do not diagnose from a screenshot alone.** A run library table was reported here as truncated
at the right edge; the layout was a flexible column plus a fixed card, which fits any width, and the
screenshot was simply cropped. Check the code before recording a finding.

**9. Editing tools cannot write to any XAML file that already exists.** Not `Themes/*.xaml`
specifically — **every** existing `.xaml` file, views included. `Controls.xaml` and `App.xaml` both
refused; a newly created `Themes/Tree.xaml` was then edited by the same tool without complaint, and
`create_file` writes into `Themes/` happily. So the rule is *existing* XAML, not the folder and not
the file type. **Corrected 2026-08-18**; the earlier wording sent a session to the terminal for the
wrong reason and would have sent the next one there too.

The remedies that follow from it: put new visual vocabulary in a **new** dictionary and merge it in
`App.xaml`, and make any edit to existing XAML through the terminal. Verify with
`git diff --numstat` afterwards — a stripped BOM shows up as the whole file changing.

**9a. A past session's failed write landed outside the product.** An empty
`src/SecureAD.Shell/Themes/Palette.xaml` sat at the repository root, dated 18 August 2026 — the
week lesson 9 was written. The product is under `next/`, so that path is not part of it, and the
file was never read by anything. It was deleted 2026-08-18. **If a write reports failure, check
where it went before concluding it did nothing.**

---

## What is decided

| The product… | Decided by |
|---|---|
| is a WPF window, with no third-party UI package, publishing as one self-contained executable | [`0046`](../decisions/0046-the-shell-is-wpf.md) |
| builds the screens before the judgement half, and leaves a screen out rather than stubbing it | [`0045`](../decisions/0045-the-shell-is-built-before-the-judgement-half.md) |
| never renders an unasked question as a negative answer | [`0002`](../decisions/0002-absent-view-means-degraded-run.md) |
| navigates by two tiers of tabs, and lets a tab exist before the screen behind it — provided what stands there says it reports nothing about the directory | [`0073`](../decisions/0073-navigation-is-two-tiers-of-tabs.md) |
| gives three states three treatments, and never lets colour be the only difference | [`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) |
| keeps a fact the run could not establish quiet **by default**, raising it only where the owner decides a gap carries risk | [`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) |
| never lets a run appear clean while carrying unknowns — the total belongs to coverage | [`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) |
| reserves red for critical findings, and spends none of it on the facts a capture-side screen states | [`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) |
| also spends red on the control that stops something already running — Cancel and Stop | [`0070`](../decisions/0070-red-also-marks-the-way-out.md) |
| names every colour for its meaning, in one swappable dictionary, and ships one palette | [`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) |
| is dense in tables and grids, comfortable in wizards and settings | [`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) |
| opens New Audit as a distinct act launched from Home rather than the rail, with its own header and footer | [`0057`](../decisions/0057-starting-an-audit-is-a-modal-act.md) |
| draws that act as a **card over a dimmed shell**, not a window of its own and not a page — one window, no second title bar, but unmistakably something opened *on top of* the product rather than a fourth place to be | [`0071`](../decisions/0071-the-audit-is-modal-in-effect-not-in-its-own-window.md) |
| states refusals and failures on the surface itself, in the product's colours, rather than in a `MessageBox` nothing can theme | [`0071`](../decisions/0071-the-audit-is-modal-in-effect-not-in-its-own-window.md) |
| will not run analysis while a capture is running, and says so in words rather than disabling a control | [`0072`](../decisions/0072-analysis-and-capture-do-not-run-at-the-same-time.md) |
| has **no** status bar — reversing an earlier answer, because what the predecessor's reported was live-connection state that [`0008`](../decisions/0008-live-verification-is-removed.md) removed | [`0057`](../decisions/0057-starting-an-audit-is-a-modal-act.md) |
| keeps view models free of presentation: no `Brush`, `Color`, `Visibility` or `Style` | `ShellMvvmGateTests` |
| exports no public types from the shell | [`ShellSurfaceGateTests`](../../next/tests/SecureAD.Next.Tests/Architecture/ShellSurfaceGateTests.cs) |

[`0046`](../decisions/0046-the-shell-is-wpf.md) explicitly deferred the visual language and said so:
*"The visual language is unbuilt work, and this record is where that debt is acknowledged."*
This area is that debt.

---

## What is built

The design system exists and is applied to **three screens**: New Audit, Home and Runs. The shell
now carries chrome of its own — a navigation rail and a templated table — so a screen is no longer
half in the product's language and half in Windows'.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| tell a fact the run did not measure from one it measured and found wanting, without relying on colour — four states, four silhouettes | `ViewColourLiteralGateTests` proves colour is not written into views; the shapes themselves are judged by eye against a running window, which no test can do |  |
| read a screen where no colour was chosen in isolation — every colour is named for its meaning in one dictionary | `ViewColourLiteralGateTests.NoViewNamesAColour` |  |
| trust that a colour cannot creep back into a view one screen at a time | `ViewColourLiteralGateTests.TheGateReadsTheRealViewsAndWouldRecogniseAColour` |  |
| read what became of a run in words, rather than in the name the code calls it by | `RunSummaryViewModelTests.EachStateIsShownInWords` |  |
| trust that a run state added later cannot reach a screen with no wording | `RunSummaryViewModelTests.EveryStateHasBeenGivenWordsAndAMeaning` |  |
| trust that guard is measuring something | `RunSummaryViewModelTests.AStateWithNoWordingFallsThroughToUnknown` |  |
| tell an interrupted run from a damaged one, whose remedies differ | `RunSummaryViewModelTests.InterruptedAndDamagedDoNotMeanTheSameThing` |  |
| select a run on Home and read what was observed about it | `RunLibraryViewModelTests.SelectingARunGivesTheCardSomethingToShow` |  |
| trust the details card is never left describing a run the library may no longer hold | `RunLibraryViewModelTests.ARefreshDropsTheSelection` |  |
| read a window Windows does not stretch when it moves to a monitor scaled differently | `DpiAwarenessGateTests.TheProductAsksForPerMonitorAwareness` |  |
| trust that setting is wired to the build rather than sitting in a file nothing reads | `DpiAwarenessGateTests.TheManifestIsReferencedByTheProject` |  |
| trust that guard is measuring something | `DpiAwarenessGateTests.TheGateReadsTheRealManifestAndWouldRecogniseASystemAwareOne` |  |

**Where things live.** `next/src/SecureAD.Shell/Themes/` — `Palette.xaml` (raw values, the only
file a second theme replaces), `Brushes.xaml` (meaning), `Type.xaml`, `Spacing.xaml` (both
densities), `StateMarks.xaml` (the four treatments), `Controls.xaml` (templates). Merged in
dependency order by `App.xaml`, after WPF's first-party Fluent theme.

**The chrome.** A navy ramp, held apart from the neutrals because those are chosen to be legible
and these to recede. It dresses two things and nothing else: the navigation rail, and the table
header. Neither ever states a fact, which is why a dark colour is safe on them — `0056` reserves
the state vocabulary for facts, and chrome is not one.

**Red also marks the way out** — `0070`. `DangerButton` is worn by Cancel and Stop, and by nothing
that reports. Not because stopping is dangerous, but because the exit of a three-hour read has to
be findable without reading labels. Red still may not mark a fact on a capture-side screen.

**The four marks.** Filled disc for established-and-good, filled triangle for
established-and-worth-attention, **hollow ring** for not-established, cross for a fault. They differ
in silhouette before they differ in hue: printed in black and white they are still four things,
which is the test. The hollow ring is the quietest and the only unfilled one.

**`FactState` was added to the view models**, because every fact previously reached the screen as a
finished sentence and nothing a treatment could key on. It states what the run established, not what
it should look like — a view model still holds no `Brush`, `Color`, `Visibility` or `Style`, and
`ShellMvvmGateTests` still fails the build for one.

---

## Decided per screen

`0056` fixes the default and the vocabulary; **which gaps are raised is judged screen by screen, by
the owner, against a running window.** Each answer is recorded here as it is made, so the same
question is not re-argued from first principles every time.

| Screen | Gaps raised above the quiet default | Reviewed |
|---|---|---|
| New Audit — Domains | **Proposed, awaiting review.** Raised: a controller in another site; a domain with no failover; a connection nothing answered (as a fault); the PDC emulator prompt. Left quiet: a site that could not be compared; a choice made without every input; any question not yet asked. Both PDC emulator answers are treated as good ones — a single-controller domain had no alternative, and marking all three rows of a three-domain lab would be noise. **Reconciled 2026-08-18: none of these marks are on this screen any more.** The table carries four columns and no state marks at all; every one of them is in the Details window, and the only signal left on the domains screen is the mark on the Details button, which lights when any domain has anything worth attention. What is being judged has therefore changed from *which cells are loud* to *whether one mark on one button is enough*. | **not yet** |
| New Audit — Review | **A different screen now.** It no longer repeats the table: it states how many domains will be read and from where, how many will not and why, how much the run will not establish, and what is worth knowing first. | **not yet** — the review judged on 2026-08-16 was the old one, which showed the same table under a different heading |
| Domain details | The five facts that left the table, each with its mark, its label and its full sentence. **Proposed, awaiting review.** | **not yet** |
| Home | **Proposed, awaiting review.** Two columns: the library and the launcher above, the runs taken below left, a details card for the selected run on the right. Raised: nothing. **Nothing on this screen reports posture** — `0045` means no part of this product produces a finding yet, and a card reading "0 findings" would be read as *your directory is clean* rather than *nothing has looked*. The card states what a listing observed and no more; coverage is inside the bundle and would have to be opened to be known. | **not yet** |
| Run library | **Proposed, awaiting review.** Three columns: the run, what became of it, and what that means. The third is new — a state name says what happened, and an operator needs to know what to do about it. | **not yet** |
| The rail | **Replaced 2026-08-18 by two rows of tabs** — [`0073`](../decisions/0073-navigation-is-two-tiers-of-tabs.md). What it used to say: navy, the product name at the top, Home and Runs and nothing else per `0045`, the selected entry marked by a 3px accent bar. The tabs keep the navy for the first row and give the second row an accent underline instead, so the two tiers do not look alike. First row: Home, Dashboard, Assets, Runs, Settings. Second row under Assets: Objects, Findings, LAPS — the last two showing a panel that says it is not built and reports nothing about the directory. **Neither the tabs nor the placeholders have been seen on a running window.** | **not yet** |
| Assets | **Proposed, awaiting review.** Two panes: the tree on the left, the objects of the selected container on the right. **Settled with the owner 2026-08-18, against his predecessor's screenshots:** the tree behaves like ADUC and is navigation rather than the subject; empty containers appear; **counts do not** — the predecessor had them and the owner did not remember why; paging is required. A three-way level control uses the directory's own scopes — *this object*, *one level*, *everything beneath* — and the selected container plus that level will scope the findings list too when one exists, so both read one selection rather than keeping two that can disagree. Columns are Name and Object Type, with **In** appearing only at *everything beneath*, where rows genuinely come from different containers; the predecessor's grid repeated Parent OU and Domain on all 28 rows. **No Risk column and no tab strip** — `0045`. What the run could not read is stated where it bites: a short listing says so above the grid rather than showing fewer rows. | **not yet** |

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered.

- **Whether Runs deserves a tab of its own.** **Raised by the owner 2026-08-18:** it is redundant,
  and what it does could live under Home. Home already chooses the run library and lists what it
  holds, so the two overlap by construction. Not acted on — it moves a screen the owner has used,
  and it wants judging on a running window rather than at the end of a session.
- **What the tree hides, if anything.** The Configuration partition shows `DisplaySpecifiers` and
  its numbered children (`404`, `409`, `40C`…), which are real containers nobody navigates by. An
  audit tool that hides part of a directory is a decision with teeth, so this is the owner's.
- **The polish the owner listed 2026-08-18**, none of it acted on: icons in the tree for
  organisational units, users, computers and groups; replacing the word *Assets* above the tree
  with a search box taking an OU, user or computer name; and grouping the repeated
  *"a partition this product does not read"* entries, which repeat once per DNS partition on every
  bundle.

- **What the status bar reports.** **Answered 2026-08-16: there is no status bar**
  ([`0057`](../decisions/0057-starting-an-audit-is-a-modal-act.md)). This reverses an answer given
  earlier the same day; the reason is recorded in that record rather than the first answer being
  quietly overwritten.
- **Whether coverage can produce a run-level count of unestablished facts.** **Answered 2026-08-16:
  it cannot, at the moment the New Audit screen needs it.** `RunCoverage` describes a capture that
  has not happened yet. The post-capture total exists there; the pre-capture total must be composed
  from `PreflightReport` and does not exist — `F-0056-1`.
- **Where the pre-capture total appears, and how it is worded.** With the status bar gone it belongs
  on the wizard: the Domains step, the Review step, or the modal's header beside the domain count.
  Undecided.
- **How a step in a wizard shows that it is the current step.** **Answered by
  [`0057`](../decisions/0057-starting-an-audit-is-a-modal-act.md)**: "Step n of m" in small type
  above the question that step asks, in the modal's own header. Not yet built.
- **Which columns the New Audit table carries.** Decided in principle 2026-08-16: **wide, every fact
  visible at once**, one row per domain with a state mark per fact. Accepted as provisional — the
  owner's words were *"I'll need to see it"* — so it is the first thing to review once built.
- **How an inert rail says that it is inert.** **Answered 2026-08-18.** The audit is drawn as a card
  over a scrim that covers the rail too, so what an operator sees is the whole shell dimmed behind
  the thing he is being asked to deal with — a form of words the world already understands. Neither
  of the earlier attempts survives: dimming the rail alone made it illegible, and leaving it looking
  normal while refusing clicks made the application look broken.
- **What an icon is, if the product has any.** No icon fonts and no image assets — drawn in XAML or
  not present.
- **Whether the density settled here is right.** The owner accepted dense tables with the caveat
  that they may need loosening once seen against a real forest.

---

## Open findings

**Reconciled 2026-08-18**, after the New Audit screen was rebuilt around a four-column table, a
Details window and a review screen. Several of these described a screen that no longer exists. Each
was checked against the code rather than assumed closed, and the two that need eyes on a running
window say so rather than being closed on reasoning.

| | | |
|---|---|---|
| **closed 2026-08-22.** `next/src/SecureAD.Shell/app.manifest` declares `PerMonitorV2`, and the project references it through `<ApplicationManifest>`. Both halves are needed and both are held by `DpiAwarenessGateTests` - a manifest nothing points at is a file rather than a setting, and that half would have failed silently. **The native helper project on the Microsoft page is not needed**: that page covers Windows 8.1, and *What's new in .NET Framework 4.6.2* records that "WPF in .NET Framework 4.6.2 enables per-monitor awareness", which carried into modern .NET - so WPF re-renders at the new DPI itself. Confirmed embedded in the built executable, not merely in the source. **Not yet seen on a running window across two monitors**, which is the only instrument that settles it |
| `F-0079-2` | **The run list's columns cannot be resized or reordered.** `ObjectSectionTemplates.xaml` sets `CanUserResizeColumns`, `CanUserReorderColumns` and `CanUserSortColumns` explicitly on the Assets grid; `HomeView.xaml` sets none of them. WPF's defaults are `True`, so they ought to work - which is why the other grid declaring them is a hint that somebody found otherwise. Raised by the owner, 2026-08-21. | **open, cause not established.** The suspicion is the `Width="*"` column, which resizes by redistributing and can feel inert. Declare the three properties and see; do not assume the declaration was the fix without checking, because that would leave the real cause in place |
| `F-0079-3` | **The details card is a fixed 360 pixels wide.** On a large panel it is a stamp beside a wide grid; on a laptop it crowds the list. The grid and card also do not reflow - at narrow widths they squash rather than stacking - and `ScreenPadding` is one value at every window size. | **open.** Star sizing and `Auto` with `MinWidth`/`MaxWidth` express what the layout means; a pixel count expresses one monitor. This is the same defect as `F-0056-3` one screen along |
| `F-0079-4` | **The delete confirmation is a raw `MessageBox`.** [`0071`](../decisions/0071-the-audit-is-modal-in-effect-not-in-its-own-window.md) names "a raw `MessageBox` on any refusal" among the things that made the product read as an old Windows application with a modern coat of paint, and moved the wizard's two message boxes to an in-shell banner. The confirmation added on 2026-08-21 reintroduces one, with an operating-system title bar that takes no part in the design system. | **open.** `IConfirmation` is already a seam, so this is a swap of the implementation and nothing else changes. It was built this way to get deletion working, not because a message box was judged right |
| `F-0079-5` | **The screen is very white.** Rows, cards and page are all near-white; the only colour is the navy header and the accent. `Brushes.xaml` carries a palette - subtle greens, ambers, neutrals - that the run library uses none of. Raised by the owner, 2026-08-21. | **Decision (owner, 2026-08-22): colour in this product has two duties, and they are separate.** *One is to make the visuals appealing and to assist with contrast, so groups of information are easier to read and to separate from other data. The second is for findings, where red is critical, yellow is a warning, and green is good - green being limited in its use for good.* This settles what [`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) deliberately left open: decision 5 of that record reserved "a severity ramp" for findings but named only red, and the record says nothing at all about colour used for grouping and legibility. Both duties are now stated. **What follows for this finding:** Home reports no posture - [`0045`](../decisions/0045-the-shell-is-built-before-the-judgement-half.md) - so the second duty does not apply to it, and the fix is the first duty only, drawn from the neutrals, `SurfaceRaisedBackground`, `DividerBrush` and the subtle accents, touching no state or finding brush. **Still open as work**, but no longer open as a question |
| `F-0079-9` | **Two of the three rungs of the findings ramp are already spent on capture-side screens.** Decision 5 of [`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) reserved "a severity ramp in the palette that **no screen built before findings may consume**", and in practice only red was kept back. Read from `Palette.xaml` and `Brushes.xaml` on 2026-08-22: `CriticalFindingBrush` is `Red600`, and so is `DangerBrush`, which [`0070`](../decisions/0070-red-also-marks-the-way-out.md) deliberately spends on Cancel and Stop. But `EstablishedBadBrush` is `Amber600` and `FaultBrush` is `Amber700`, both worn by capture-side state marks today, and `EstablishedGoodBrush` is `Green600`. The owner's decision of 2026-08-22 makes yellow a warning and green a good finding. So when the judgement half arrives, the amber that will mean *warning* is the amber that already means *this domain has something worth attention in the capture plan*, and the green that will mean *a good finding* is the green that already means *this fact was established and is fine*. | **open, and it is the owner's to settle.** It may not be a defect: one vocabulary reading the same way everywhere - amber is attention, green is fine - is arguable as a virtue rather than a dilution, and that record's worry was specifically about spending the *strongest* signal, which red still is and which is still reserved. But its stated reasoning covers the whole ramp and was honoured only for red, so the gap between what it reserved and what the palette did is real, and it went unnoticed until the ramp's other rungs were given meanings. **Raised now because it is cheap now**: no finding exists yet, so nothing has to be restyled. At thirty screens it would be brutal, which is the same shape of reasoning that record used about red |
| `F-0079-7` | **A report that the run grid rendered its columns in an order its XAML did not declare.** Recorded on 2026-08-21 as: `HomeView.xaml` declares Run, When, Outcome, and the running app showed Run, Outcome, When with the Outcome header wrapped to "Out com e". A grid disobeying its own declaration would be worth understanding rather than working around. | **did not reproduce, and the original report is doubted.** Checked twice against screenshots of the running app on 2026-08-21, before and after the grid was rebuilt: the order was Run, When, Outcome both times, as declared. The declaration cited in the report was also slightly wrong - Outcome was on line 104, not within the 86-101 range given. The wrapped header was real and had a mundane cause, fixed as part of `F-0079-3` work: the Outcome column was too narrow, so its header wrapped to three lines while its value clipped to "Finishe". **The likeliest explanation is that a clipped, three-line header was misread as a column in the wrong place**, but that is a guess and is labelled one. Left here rather than deleted, because a session that sees it recur should know it was looked for and not found |
| `F-0049-1` | **The only `RadioButton` style is the rail's, and it is invisible on a screen.** The implicit style in `Controls.xaml` dresses a rail entry: light text for a navy background, with the selected one filled. Worn on a white surface an unselected option is white on white. Found on the owner's first look at Assets, 2026-08-18 — two of the three level options could not be read until clicked. | **half closed.** Assets now uses a keyed `ChoiceButton` style, in `Themes/Choices.xaml`, meant for a light surface. **The trap itself is still set:** the next screen to use a plain `<RadioButton>` inherits the rail's style and gets the same invisible control. The fix is to key the rail's style as well and name it on the three rail entries, leaving the implicit style safe for screens — deliberately not done in the same session that found this, because it restyles a rail that has been looked at and judged right |
| `F-0056-3` | **A screen may not scroll horizontally.** Nine columns of sentences did not fit a laptop, so half of what the run established was off the edge. | **believed closed, needs a look.** The table carries four columns — Include, Domain, Read from, and the override — and the five that carried sentences moved behind Details. Whether four fit is a question only a running window answers, so this stays open until seen |
| `F-0056-4` | **Truncated sentences.** Cells cut mid-word, so a sentence written to distinguish what was measured from what was not said something else. | **closed.** The trimming lived in one `FactCell` template used by the five fact columns. Those columns moved to Details, where each sentence is shown in full and wrapped; the template was left behind unreferenced and has been deleted |
| `F-0056-5` | The state marks sat at the left of each cell, hard against the previous column's text, so a mark looked like it belonged to the value on its left. | **moved, still open.** No mark remains in the table — they are all in the Details window now, where they sit beside a label in a grid rather than at a cell edge. Whether that reads correctly is a question for the same look |
| `F-0056-1` | The pre-capture total of unestablished facts does not exist. | **closed 2026-08-16.** Built in `S-46`: one forest-wide number on the review screen, counted from the same three-state marks the table renders, and saying it is not yet known rather than showing a zero. `NewAuditViewModelTests.TheCountOfWhatWillNotBeEstablishedComesFromTheStatesTheTableShows` |
| `F-0056-2` | The shell merges WPF's first-party Fluent theme beneath this design system, and only the controls listed in `Controls.xaml` are overridden, so a screen can end up half in each language. | **still half closed. One more piece taken 2026-08-18:** the table header was rendering **dark text on the dark navy header and could not be read**, though the style naming white on navy was right and had been there all along. Fluent's `DataGrid` style sets `ColumnHeaderStyle` *on the control*, and a style set on a control beats an implicit one — so the product's header style was never reaching the header. Fixed by keying that style as `TableColumnHeader` and naming it on all three grids. **This is the shape to expect for the rest of `F-0056-2`: not a missing style, a style that is present and outranked.** Scrollbars, tick boxes, text fields and the Validate buttons are still Fluent's |
| `F-0071-1` | **The inert rail was drawn illegibly.** While a run is planned the rail is disabled; it was also dimmed to 45% opacity to say so, and the rail's text is a pale grey on navy — at 45% Home and Runs all but vanished. Found on the owner's first look, 2026-08-18. | **closed.** The dimming is removed and the rail stays legible. **The question it reopened is now answered too:** the audit is drawn as a card over a scrim that covers the rail as well, so the dimming an operator sees is the scrim saying *deal with this first* rather than a rail pretending to be broken. Unselected rail text was also brightened a step, having read too dark on navy |
| `F-0071-6` | **The audit read as a fourth place to be.** Hosted in the shell it looked like a page reached from the rail, which is exactly what [`0057`](../decisions/0057-starting-an-audit-is-a-modal-act.md) refused: starting an audit is an act, not a destination. The owner said so twice before it was acted on. | **believed closed, needs a look.** It is now a card over a scrimmed shell, sized like the dialog it replaced. Whether it reads as *opened over* rather than *navigated to* is the judgement only a running window settles |
| `F-0071-4` | **Stop was offered when nothing was running**, in the colour [`0070`](../decisions/0070-red-also-marks-the-way-out.md) reserves for the exit of a running thing, telling an operator a capture was under way when none was. `CanStop` is computed from `IsBusy` and nothing announced it when the opening pass ended, so the button held the value it read at load. It survived while the wizard was its own window because the binding was evaluated before the pass began; hosting it in the shell changed that order. | **closed 2026-08-18.** `NewAuditViewModelTests.TheWayOutOfTheOpeningPassIsWithdrawnWhenThePassEnds`, which asserts the announcement rather than the value — reading `CanStop` alone would pass against this exact bug. Mutation-tested in both directions |
| `F-0071-5` | **The surface was two thirds empty.** Three domains in a table stretched the full width of a maximised window, so the eye travelled 1300px to read a row that needed a third of that. The wizard used to get its proportions free from being a 980-wide window, and hosting it in the shell took that away without replacing it. | **believed closed, needs a look.** The body is capped and left-aligned. Whether the cap is right, and whether a capped body under a full-width footer reads as one thing, is a question only a running window answers |
| `F-0071-7` | **A warning on the review screen did not say which domain it was about.** Six warnings, three of them word-for-word repeats of the other three, because each domain contributed the same two sentences and the sentences say *"this domain"* — which reads fine on a row and means nothing on a summary. An operator could not tell which domain to act on, or that he was reading three domains rather than one repeated six times. | **closed 2026-08-18.** Each warning is now prefixed with the domain it concerns. **Not guarded by a test**, deliberately: the fixtures produce no warnings, so a test written against them would pass whether or not the naming worked — a check measuring nothing. A fixture that produces a warning is owed |
| `F-0071-8` | **The review screen is a wall of text.** Five headings, a two-column list, a count, a list of warnings, a button and two file paths, all at the same weight with nothing grouping them. Nothing is wrong on it; nothing helps the eye either. Raised by the owner, 2026-08-18. | **open.** Wants the section grouping the rest of the product uses — the `Card` style exists and this screen uses none of it. Also `"3 domain(s)"` and `"0 domain(s)"` are machine phrasings that reached a screen |
| `F-0056-6` | An empty table looked exactly like a table that had loaded and found nothing. | open |
| `F-0071-2` | **The details panel and its scrim have never been seen.** `DomainDetailsWindow` became a panel over the audit surface behind a navy scrim at a third. Whether the surface beneath reads as present-but-not-in-use, the way a window's shadow used to say it, is a question for a running window. | **open, needs a look** |
| `F-0071-3` | **The notice banner has never been seen.** Two `MessageBox` calls became one banner between the step question and the work, in the fault brushes the footer already uses. Whether a refusal there is found by an operator who has just typed a host name — the thing the message box guaranteed by blocking — is the risk this change took. | **open, needs a look** |
| — | `Connection` shows the raw enum name `SignedAndSealed` where every other line is a sentence | **closed.** `NewAuditViewModelTests.TheRungIsShownInWordsRatherThanAsAnEnumName` |
| — | a domain row is headed by its distinguished name while the line beneath uses the DNS name | **closed.** `NewAuditViewModelTests.ARowIsHeadedByTheNameTheForestDeclaredForTheDomain` |
| — | the wizard's step indicator does not indicate | **overtaken.** It was closed by [`0057`](../decisions/0057-starting-an-audit-is-a-modal-act.md) with "Step 2 of 2" above the question; the indicator was then removed altogether on the owner's judgement, because two screens with Next and Back do not need one |
| — | the Runs table showed `RunState` verbatim, so a stopped run read "Cancelled" and a running one "InProgress" — the names chosen to be unambiguous to a compiler, put in front of an operator | **closed 2026-08-18.** `RunSummaryViewModel` gives each state a form of words and a sentence saying what to do about it. Found while styling the grid, not looked for |
| — | a run's state was shown with nothing saying what it meant, though `Interrupted` and `Damaged` are separate members *because* their remedies differ | **closed 2026-08-18.** `RunSummaryViewModelTests.InterruptedAndDamagedDoNotMeanTheSameThing` |
