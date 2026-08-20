# 0045 - The shell is built before the judgement half, so that the rest can be reviewed

Date: 2026-08-14
Status: Accepted

Records the sequencing decision taken with the owner during `S-34`. The session was convened as a
review with no code, and this is one of two records it produced.

## Context

The evidence half of the product works. A run connects to a forest, reads every partition, reads
the Group Policy files on SYSVOL, and seals a bundle that states what it covered and what it
missed. The judgement half does not exist: reading a bundle back (`C16`-`C28`), deriving
relationships (`D1`-`D9`), evaluating rules (`E16`-`E19`) and reporting findings (`E10`-`E15`) are
all *Not started*, and nearly all are undecided.

There is no shell either. The new tree holds four projects - `SecureAD.Kernel`,
`SecureAD.Evidence`, `SecureAD.Audit`, `SecureAD.Cli` - and not one window. The whole of `J1`-`J20`
is unbuilt. The old application's shell at `src/SecureAD.UI` was not brought across and, because
the new product is not an exact rebuild of it, is reference material rather than a specification.

Two orders were argued. **One rule end to end** would prove the whole machine works by driving a
single rule from sealed bundle to reported finding. **The shell first** would build the window,
navigation and run library over the evidence layer that already exists.

The case initially made for one-rule-first was that building screens before findings exist means
building them against invented shapes, and rewriting them when the real shapes arrive. **That
argument was checked against the tree and did not survive.** It is true only of screens driven by
findings. The screens actually wanted - home, run library, capture - bind to `RunLibrary`,
`RunSummary`, `RunState`, `RunStateReader`, `RunCoverage` and `RunComparability`, all of which are
built, tested and settled. There is nothing to invent and nothing to rewrite.

What decided it was not visibility but **reviewability**, and the distinction matters. The owner is
a security and Active Directory administrator, not a developer. Today, the evidence that a row is
correct is a passing test and a slice document - engineering artifacts offered as proof that a
product behaves correctly, to the one person whose judgement about product behaviour cannot be
substituted. There is nowhere for him to exercise that judgement except on paper.

## Decision

**The shell is built before the judgement half.** The first slice is the single-window host,
navigation, a home screen, a run library bound to the real run types, and a Run Audit action wired
to the real capture path against a live forest.

**The reason is reviewability, not visibility, and this record does not pretend otherwise.** There
is no technical blocker forcing this order. The shell is built first because it is the instrument
every later row is measured with: once it exists, a findings screen lands somewhere the owner can
open, use, and say *that is not what an administrator would look for*. That judgement is his, it is
the one thing the engineering cannot supply, and it is currently unavailable to him.

**Run state is shown coarsely at first.** A capture is launched from the shell and shown as
`InProgress`, then `Sealed`, `Failed` or `Cancelled`, read from disk by `RunStateReader`. There is
no per-partition or object-count reporting anywhere in the capture layer, and adding it is work
inside that layer rather than on a screen. It is deferred to a session that is already there.

**The run library must not assume a run is a finished thing.** It binds to run state in a way that
tolerates the state changing while displayed. This costs nothing now and would be a rewrite later,
which is the whole reason it is written down rather than left to be noticed.

**No screen is stubbed.** The dashboard, reports, drift detail and offline directory tree are left
out entirely rather than built as empty scaffolding. A screen that appears to report and reports
nothing is the failure this repository already guards against elsewhere, and it is worse on a
screen than in a test, because a screen is what a customer believes.

## Consequences

**The judgement half starts later than it otherwise would.** That is the cost, it is real, and
nothing here reduces it. The product still says nothing about a customer's directory, and will not
until `C16`-`C28`, `D1`-`D9` and `E16`-`E19` are decided and built.

**The shell will be built against a smaller surface than it will eventually serve.** That is the
saving. A public shape is cheap to settle at zero consumers and expensive at many, and the shell is
the largest consumer this codebase will have.

**Later rows become reviewable rather than merely reported.** Every row after this one can be shown
working, not described as working. This is the benefit being bought, and if it does not materialise
- if the owner finds the shell no more useful than a slice document - this record was wrong and
should be revisited on that evidence.

**Screens bound to findings are deferred, not designed.** Nothing here decides what a dashboard or a
report looks like, and no part of the first slice should be read as having settled that.

**The decision does not reopen simply because the judgement half becomes urgent.** It reopens if the
shell fails to give the owner the review surface it is being built for.
