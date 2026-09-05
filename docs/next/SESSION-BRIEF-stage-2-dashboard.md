# Session brief — stage 2: the dashboard

> **Written 2026-09-05.** A brief states the objective and the known ground. It is not authoritative:
> where it disagrees with the code, the code wins and the disagreement is a finding.

## The objective

Build **stage 2 — dashboard: coverage and inventory**, the last unstarted stage below stage 6.

`docs/ROADMAP.md` § Stage 2 defines it: *"Counts over evidence already captured: users, computers,
groups, OUs, GPOs, and which domains and partitions were fully read. No rules, no graph."* Its
witness type is `DashboardViewModel`, and `check-stage-status.ps1` reports the stage built when that
type exists under `next/src` and is reachable.

**Decided by the owner, 2026-09-05**, recorded in `docs/WHAT-THE-PRODUCT-IS.md` § Build order: the
dashboard is built **before** the remaining rules. Stage 2 depends on nothing unbuilt, and putting a
screen in front of an administrator is the only way to find out whether the wording reads correctly
to the person who has to act on it.

## Correct this before you start

**A previous session told the owner the product "has no screen that shows findings to anybody". That
was wrong**, and the brief would mislead you the same way if it were not said plainly here.

The shell is real and it works. `AssetsPane` has four panes, all built and bound to live stores:

| Pane | Shows | Reads |
|---|---|---|
| `Objects` | the captured directory as a tree | sealed evidence |
| `Findings` | what the rules concluded, narrowed by the tree | the judgement store |
| `Laps` | which machines manage their local administrator password | sealed evidence |
| `Rules` | what was checked and what each check did | the judgement store |

So findings **are** visible today. The `Dashboard` member of `ShellSection` exists and renders
`NotBuiltView`, which says plainly that it is not built and **never renders an empty result** — an
empty dashboard would tell an administrator his directory is clean.

**What is genuinely missing is the answer to "what am I looking at".** An operator opening a run
lands in a tree of eight thousand objects with no sense of the forest's size, how much of it was
read, or whether the capture was complete. That is stage 2.

## What it must not do

**This is the trap the stage exists to avoid.** A dashboard is the easiest screen in the product to
make dishonest, because a number with no denominator always looks like an answer.

- **A count is not coverage.** *4,102 users* means nothing without *of how many, and were they all
  read*. `ReadCoverage` and `EvidenceCompleteness` already record what was and was not read; the
  dashboard must show the gap, not hide it behind a total.
- **Never let "could not read" render as zero.** This is failure class 2 in
  `.github/copilot-instructions.md` — the product telling a customer something false. A partition
  that was refused must look different from a partition that was empty.
- **No rules and no graph**, per the roadmap. Findings have a screen already; duplicating a severity
  count here invites two numbers that disagree.
- **Do not report a total the evidence cannot support.** `F-S24-1` found that a Windows Server 2025
  controller silently strips confidential attributes from an unencrypted search, which is why
  `MayBeMissingConfidentialValues` exists on every object. A dashboard is exactly where that would
  be flattened away.

## Where things are

| Path | What it is |
|---|---|
| `next/src/SecureAD.Shell/ViewModels/ShellSection.cs` | navigation members; `Dashboard` already present |
| `next/src/SecureAD.Shell/ViewModels/AssetsViewModel.cs` | the closest working example of a pane over a store |
| `next/src/SecureAD.Shell/ViewModels/RunSummaryViewModel.cs` | already summarises a run for Home |
| `next/src/SecureAD.Shell/Views/NotBuiltView.xaml` | what `Dashboard` renders today |
| `next/src/SecureAD.Evidence` | `ReadCoverage`, `EvidenceCompleteness`, the bundle reader |
| `docs/layers/shell/` | layer documents; a new one is required for this screen |
| `docs/ROADMAP.md` § Stage 2 | the definition above |

**A lab bundle with real data**: `C:\Users\ba.admin\SecureADRuns\ad.lab-20260905-035415` — three
domains, ~8,380 objects, 26 findings. It contains **planted positives**; `Set-LabOwnershipAndTakeover.ps1 -Remove`
clears them.

## How this repository expects work to be done

- **Every gate carries a self-test.** A check that passes while measuring nothing is failure class 1.
  A dashboard test that counts an empty bundle and asserts zero passes forever and proves nothing.
- **A green test proves nothing until it has been watched failing.** Mutate, observe, revert — one at
  a time.
- **Verify against the lab, not only fixtures.** `F-S45-7` was a false claim that survived a thorough
  fixture suite because no fixture contains a real directory. `F-S45-6` was a rule that could never
  fire, found only by planting a positive.
- **Standing constraints**: never `Get-Content -Raw`; the document encoding count must stay **14**;
  edit `PUNCH-LIST.md` at line boundaries with no unescaped pipes; delete scratch scripts;
  PowerShell commands use `;` rather than newlines.
- Full suite: `cd next; cmd /c "dotnet test SecureAD.Next.sln --nologo > %TEMP%\out.txt 2>&1"`.
  Currently **3,153 passing**.

## Open questions for the owner — ask, do not guess

1. **What does an administrator want to see first on opening a run?** The roadmap names the counts;
   it does not say what belongs at the top, and that is a judgement about his working day.
2. **What should the dashboard say when a domain was only partly read?** There is a real
   choice — show the partial number with a warning, or refuse to show a number at all.
3. **Should the dashboard be the landing screen for a selected run**, replacing the current
   behaviour, or a destination the operator chooses?

## Definition of done

- `DashboardViewModel` exists, is reachable, and `check-stage-status.ps1` reports stage 2 built.
- The screen distinguishes *read and empty* from *not read*, and a test proves it by mutation.
- A layer document under `docs/layers/shell/` describes the screen and what it refuses to claim.
- `docs/ROADMAP.md` stage 2 updated with what was built and what it was verified against.
- Verified against the lab bundle, with the numbers checked against the directory by hand.
- Full suite green; encoding count 14.
