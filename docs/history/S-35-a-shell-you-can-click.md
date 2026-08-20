# S-35 — A shell you can click

> **This records session S-35 as of 2026-08-10. Nothing here states current behaviour.**  
> It is kept for the reasoning it carries, not as documentation. See [`docs/history/README.md`](README.md).

Follows `S-34`, which was convened as a review and produced no code. This session produced two
decision records and the first shell.

## What the owner decided, and why the prior answer was wrong

`S-34` recorded that the owner had chosen *one rule end to end* over *a GUI shell*, then chose to
review first. This session reopened that, at his instigation, and **the earlier choice did not
survive contact with the tree**.

The argument for one-rule-first was that screens built before findings exist are built against
invented shapes and rewritten when the real shapes arrive. Checked against the code, that is true
only of screens driven by findings. The screens actually wanted — home, run library, capture — bind
to `RunLibrary`, `RunSummary`, `RunState`, `RunStateReader`, `RunCoverage` and `RunComparability`,
all built, tested and settled. There was nothing to invent.

What decided it was the owner's point, not the engineering's: **he cannot review anything.** The
evidence that a row is correct is currently a passing test and a slice document — engineering
artifacts offered as proof of product behaviour to the one person whose judgement about product
behaviour cannot be substituted. A shell is the instrument every later row is measured with.

Recorded as [`0045`](../decisions/0045-the-shell-is-built-before-the-judgement-half.md).

## The framework, decided on two measurements

The owner set two constraints: no third-party dependencies, and it must not look like default WPF.
Those pull against each other, because the usual way to make WPF look modern is a third-party theme.
WinUI 3 was examined seriously rather than dismissed, on his instruction to look at the predecessor
and form a view. Two measurements settled it:

- **The product is grid-shaped.** Twenty-one of the predecessor's thirty-six XAML files use
  `DataGrid`, and grids have a map document of their own. WinUI 3 has no first-party `DataGrid`.
- **The product ships as one file.** WPF supports `PublishSingleFile`; WinUI 3 does not. Losing that
  means an installer or a folder, for a tool that gets copied onto a jump host and run.

Recorded as [`0046`](../decisions/0046-the-shell-is-wpf.md). The single executable was **verified by
publishing, not asserted**: it needs `IncludeNativeLibrariesForSelfExtract`, without which six
native WPF libraries sit beside the exe. The record was corrected once that was measured.

## What the GUI surfaced that a rule slice would not have

Asked where the run library should live by default, the owner answered that **the application is
supposed to let the operator set it**. That requirement appeared the moment a screen was put in
front of him, and [`0025`](../decisions/0025-the-run-library-is-a-managed-root.md) had already ruled
there must be no default — the predecessor hardcoded `%LOCALAPPDATA%` into two constructors.

So a persisted setting was in scope, though the settings screen was not. This is the argument for
`0045` proving itself inside the session that made it.

## What was built

- `SecureAD.Shell`, WPF, publishing as `SecureAD.exe`. The command line was renamed to
  `securead-cli.exe`: Windows filenames and assembly resolution are both case-insensitive, so
  `SecureAD` and `securead` are one name, and `CommandLineSurfaceGateTests` had already loaded the
  wrong one and reported the window's types as the command line's surface.
- `RunLibrary.List()` and `RunListing` in the evidence layer, so a run library screen has something
  to bind to. A directory that is not a run is skipped; a run that exists and cannot be trusted is
  listed as `Damaged` with its explanation. The two are different and are kept different.
- Home and Runs, over the real evidence layer, with Run Audit driving `CaptureSession` — the second
  caller [`0039`](../decisions/0039-one-way-to-start-a-capture.md) anticipated, not a second way in.
- `ShellMvvmGateTests`: a view model names neither a screen type nor the disk, code-behind does
  nothing but `InitializeComponent`, and only `App.xaml.cs` constructs a concrete service.

Reporting is coarse. `RunState.InProgress` is observed from the bundle; there is no per-partition
progress anywhere in the capture layer, and inventing one on screen would be a picture of a run
rather than a report of it.

**Nothing bound to findings was built, and nothing was stubbed.** No dashboard, no reports, no drift
detail, no directory tree. A screen that appears to report and reports nothing is worse than an
absent one, because a screen is what a customer believes.

## What went wrong, and what caught it

- **A gate passed while measuring nothing.** `OnlyTheCompositionRootAssemblesTheProduct` reported
  clean while `new FolderPicker()` sat in a view model: `RebuildTree.Scan` wraps terms in word
  boundaries, and a term ending in `(` can never match one. The guard was structurally incapable of
  firing. Found only by mutating it. Rewritten, re-proved, and its scanner self-test now asserts the
  construction scan can find a real site. **`RebuildTree.Scan` is unsuitable for any term that is
  not a bare identifier**, which is worth knowing before the next guard is written with it.
- **The shell was never in the solution.** `dotnet sln add` failed silently and the project compiled
  only transitively through the test project's reference. Caught by `GreenfieldGateTests`.
- **Five pre-existing architecture gates fired** at the new project — surface register, architecture
  document, greenfield, command-line surface, and layering. All were answered rather than
  suppressed. `SecureAD.Shell` sits on layer 5 of its own, because two projects sharing a layer may
  reference each other without the downward rule noticing.
- **The editor stripped a UTF-8 BOM twice**, and destroyed the `J44` ledger row once. Both caught by
  the documented `git diff --numstat` check and by `InventoryCompletenessTests`.

## Owed from here

- **Where configuration lives, and what else is configurable.** One setting exists —
  the run library path. Nothing has decided what else the operator sets, where it belongs, or
  whether a machine-wide answer is ever right. The owner raised this at the close of the session.
  **Settled immediately afterwards by
  [`0047`](../decisions/0047-settings-are-per-user-and-per-machine.md):** per-user and per-machine
  in `%LOCALAPPDATA%\SecureAD`, local rather than roaming because a run library is expected to be a
  local disk and a roamed path is a confident answer that is wrong on the next machine. The run
  library path remains the only setting. **Logs are still owed** — the owner deferred them, and the
  prior question is what a log would carry that the sealed bundle does not already record.
- **The visual language** (`J3` chrome, and the styling the owner deferred until he had seen it
  plain).
- **Live capture progress** (`J10`) — capture-layer work, not screen work.
- **The judgement half**, still untouched: `C16`–`C28`, `D1`–`D9`, `E10`–`E19`.
