# 0039 - There is one way to start a capture, and it runs unattended

Date: 2026-08-14
Status: Accepted

## Context

This decision has governed the write path since 2026-08-12 and had no record. It existed as an
owner ruling quoted in a session note, restated in ledger row `C15`, and restated again in
`BundleWriter`'s class remarks - three copies, no source.

That is not a filing complaint. The copies said *the entry point takes a destination*, and
[`0025`](0025-the-run-library-is-a-managed-root.md) decided two days later that the tool owns a
configured root and that capture to an arbitrary path is not offered. Nothing swept the copies. On
2026-08-14 a reader following the ledger reached the superseded answer, because the ledger was the
document in front of them and the decision record was not.

A measurement taken the same day: each decision record is referenced in an average of sixteen other
files, and sixty sentences of sixty characters or more appear verbatim in two or more files. At that
fan-out a decision that changes needs sixteen correct edits to avoid contradicting itself.

The substance also deserved a record on its own account. The predecessor is a WPF application: a
capture was something an operator started by clicking, and there was no other way to run one. Moving
away from that is a real change and the reasoning for it was never written down anywhere.

## Decision

**There is one entry point into capture.** Not one per surface, not one for capture and another for
re-analysis. Two ways to start a capture is two capture behaviours, and the first sign they have
diverged is a bundle that came out different depending on how it was started.

**It takes the run directory it is given, and does not choose one.** Where that directory comes from
is settled by [`0025`](0025-the-run-library-is-a-managed-root.md) and is not restated here.

**It completes without anyone watching.** No prompt, no dialog, no question at the moment of
failure. A capture of a large forest is hours, an audit tool is scheduled, and a run that blocks at
03:00 on a prompt nobody sees has produced nothing by morning. This is the same reasoning that
[`0018`](0018-connection-security-is-an-ordered-ladder.md) used to forbid a dialog on connection
failure and that made the retry policy report rather than ask.

**A window drives that same entry point.** A graphical surface is a caller, not a second
implementation. It may collect arguments and show progress; it may not decide anything the entry
point decides.

**What this decision does not settle is whether the executable is a console application.** That is
packaging. The requirement is one entry point that runs unattended, and both a command and a window
that shells into it satisfy it.

## Consequences

Capture is schedulable from the day the entry point exists, and analysis is offline against the
bundle per [`0013`](0013-the-bundle-is-no-longer-a-two-way-contract.md), so capture at 03:00 on a
member server and analysis on a workstation a week later is the ordinary workflow rather than a
workaround.

An unattended run cannot ask for a declared allowance, and per
[`0018`](0018-connection-security-is-an-ordered-ladder.md) the allowance is per run and never
remembered. So a scheduled run passes it as an argument each time or not at all, and a controller
that will accept nothing better ends the run rather than silently downgrading it. That is the right
failure, and it is a failure the operator reads in the morning rather than a bundle.

Nothing may restate this record. Rows, comments and notes cite `0039`.
