# S-46 — The exclusion attestation, and what an operator is told he will not know

Produces: the exclusion step in the New Audit window, a slice document describing it, and the
capabilities added to [`docs/areas/the-new-audit-wizard.md`](../../areas/the-new-audit-wizard.md).
Governing records: [`0062`](../../decisions/0062-what-an-exclusion-attestation-asks-for.md),
[`0059`](../../decisions/0059-an-exclusion-is-attested-once-per-run.md),
[`0054`](../../decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md),
[`0063`](../../decisions/0063-excluded-never-looks-like-unreachable.md),
[`0056`](../../decisions/0056-the-visual-language-encodes-three-states.md),
[`0052`](../../decisions/0052-the-domain-is-the-only-unit-of-scope.md). No new records expected
unless the owner answers one of the questions below, in which case that answer is a record.

## Why this session exists

**The product has decided something its screen cannot do.** `0062` settles what an exclusion
attestation asks for — a reason, an account, and an authorising name. `0059` settles that it is
asked every run and never carried forward. `0054` settles that a domain with no candidate
controllers *is* an exclusion and must be attested rather than dropped.

**The wizard has no step for it.** So a decision with `Status: Accepted` is currently unenforceable,
and a domain can leave a run without anyone putting their name to it.

### What changed under this brief before it was run

`S-47` was taken first, at the owner's direction, and moved several things this brief describes.
None of it changes what the session must produce; all of it changes what it will find.

- **The window works itself out when it opens.** Both passes - discovery and the per-domain check -
  run on `OpenAsync` without a press, land on the **Domains** step, show an indeterminate indicator
  and can be cancelled. The two buttons this brief may imply are gone; the footer action from
  Domains is **Next**.
- **There is a dialog seam now.** `INewAuditDialog` has `ShowRefusal` and `ShowProblem` beside
  `Show`, both faked in `ShellFakes` as recorded lists so a dialog can be proved without a person to
  dismiss one. **The attestation dialog belongs behind that same seam.**
- **`F-S41-4` is closed**, so this brief's *out of scope* note about it is spent. Checking a typed
  controller now costs one connection to one machine, via `NamedControllerCheck`.
- **The table was trimmed** on 2026-08-16 - ten columns to eight, fixed widths removed, `Failover`
  and `Choice` moved beneath the row. **The owner has since asked to review the columns again after
  this session**, because an *Include* column changes what the rest of the table is for. So the
  column review is still out of scope here, but it now follows this work rather than being unrelated
  to it.
- **The owner has already answered part of question 1.** He asked for an **Include** column of tick
  boxes on the domain row, and for unticking a domain to raise the attestation as a pop-up. The rest
  of question 1, and questions 2 to 4, are still open.

The second half is `F-0056-1`, open against this area. `0056` decides every fact shows in three
states — established, established as absent, and not established. Nothing adds the third state up.
**Before committing a run, an operator cannot see how much this audit will not know.** He can see
each unknown one at a time, in a table, and nowhere is he told there are eleven of them.

Both belong to the same moment: the last screen before a run commits.

## What is already decided, so the session does not re-argue it

- **What the attestation asks for**, and that it is per run — `0062`, `0059`. Do not redesign the
  fields.
- **A domain with no candidates is an exclusion, not a gap** — `0054`. It is shown, not omitted,
  and `DiscoveryWiringTests.ADomainWithNoCandidatesIsShownRatherThanOmitted` already proves the
  showing.
- **Excluded never looks like unreachable** — `0063`. Two different states, two different
  renderings, never one.
- **The domain is the only unit of scope an operator may change** — `0052`. There is no
  per-OU or per-object exclusion and this session does not invent one.
- **Starting an audit is a modal act** — `0057`. The attestation lives inside that window.
- **Nothing on screen may state a fact the run did not measure** — the standing rule from `S-41`,
  and `0002` underneath it.

## Questions only the owner can answer

**Ask these before writing code. Do not infer an answer from the predecessor, from an inventory row,
or from the shape of the existing view models.**

1. **Where the attestation is asked for.** *Partly answered*: the owner has asked for an **Include**
   tick box on the domain row, with unticking raising the attestation as a pop-up. What remains is
   whether anything else changes - whether the stepper gains a step, and where a domain with no
   candidates is attested from, since it has no tick to untick.
2. **Whether an unattested exclusion blocks the run, or merely marks it.** `0059` says it is asked;
   it does not say what happens when the operator declines to answer. Nor what happens to the tick
   box when he dismisses the dialog without completing it.
3. **What the pre-capture total actually counts, and what it is called on screen.** *"Eleven facts
   this run will not establish"* is one shape; a per-domain count is another. This is what an AD
   administrator has to act on, so the wording is his.
4. **Whether a domain excluded by choice and a domain with no candidates share one attestation
   dialog**, given `0054` makes both exclusions and `0063` insists they never look alike.
5. **How much of `0062` this session builds.** `0062` says the whole attestation reaches the bundle -
   the reason, the free text, both names and the time. That is a table and a write, not only a
   dialog. A session that builds the dialog alone leaves the screen collecting an attestation that
   goes nowhere and `0062` still unenforced, so if the bundle half is deferred it is deferred
   deliberately and with a finding raised.

## Scope

**In.**

1. **The exclusion attestation**, wherever the owner puts it: the three fields `0062` names, asked
   once per run per `0059`, for both kinds of exclusion.
2. **The pre-capture total of unestablished facts** — `F-0056-1` — on the last screen before the
   run commits.
3. **A slice document** describing what the step does and refuses, bound to the code by a test that
   derives what it expects from the code rather than pinning prose.
4. **The area file updated**: every new capability added to its *What is built* table naming the
   test that proves it, and any question this session answers moved out of *What has not been
   discussed*.

**Out, deliberately.**

- **`F-S41-4`** — **closed by `S-47`** and no longer anything to do. Checking a typed controller now
  costs one connection to one machine.
- **Where a running capture reports itself.** `0060` decides the content, not the placement. Its
  own session.
- **Whether the modal can be closed mid-run.**
- **The column review.** Still out of scope, but it now **follows this session**: the owner has
  asked to judge the columns once the *Include* column exists, because that column changes what the
  rest of the table is for.

## Where this starts

- [`docs/areas/the-new-audit-wizard.md`](../../areas/the-new-audit-wizard.md) — read it whole. Its
  *What is built* table names thirty capabilities that already exist; several are about telling a
  question not yet put apart from a no, which is the same grammar this session extends.
- [`0062`](../../decisions/0062-what-an-exclusion-attestation-asks-for.md) and
  [`0059`](../../decisions/0059-an-exclusion-is-attested-once-per-run.md), whole.
- `next/src/SecureAD.Shell/` and `NewAuditViewModelTests`, `DiscoveryWiringTests` — what the screen
  already does, and the vocabulary its tests are written in.
- `next/src/SecureAD.Shell/Services/INewAuditDialog.cs` and `ShellFakes.cs` — the dialog seam and how
  a dialog is proved without a person to dismiss one. The attestation goes behind this.
- [`docs/history/S-47-a-window-that-discovers-on-its-own.md`](../../history/S-47-a-window-that-discovers-on-its-own.md)
  — what moved most recently, and why the table looks as it does.

**A note on searching this repository.** `git grep` and `git ls-files` are the only searches to
trust here; the built-in file search returns empty results for tracked files under `docs/`.

**A note on the predecessor.** [`WHAT-THE-OLD-APP-HAD.md`](../WHAT-THE-OLD-APP-HAD.md) rows tagged
`the-new-audit-wizard` are research and nothing more. The old app's exclusion dialog refused an
exclusion without a stated posture, and its untick-a-domain flow existed for one-way trusts that
[`0051`](../../decisions/0051-trusts-describe-a-boundary-and-never-widen-a-run.md) removed the need
for. Read it to know what was tried; do not carry its shape across.

## Rules

- **Nothing on screen states a fact the run did not measure.** The standing rule of this area. A
  count of unestablished facts is itself a fact — if it cannot be computed, it says so rather than
  showing zero.
- **Three states, never two.** `0056`. Established, established as absent, not established. A
  boolean anywhere in this work is a defect.
- **Every capability added to the area file names the test that proves it**, and the test derives
  what it expects from the code. `AreaFileGateTests` fails the build otherwise.
- **No golden value or frozen fixture is edited.** If one needs changing, that is a finding and the
  work stops.
- **A new gate carries its scanner self-test**, per [`docs/next/README.md`](../README.md) § Gates.

## Finish by

- An exclusion cannot leave a run without the three things `0062` names, and the test proving it
  names the refusal in the product's own words.
- An operator sees, before committing, how much the run will not establish — and sees it as a
  number he can act on rather than eleven cells he must find.
- A domain excluded by choice and a domain with no candidates are told apart on screen, per `0063`,
  and a test fails if they are rendered alike.
- The area file's *What is built* table has grown, and its *What has not been discussed* section has
  shrunk by exactly the questions this session answered.
- The solution builds and the whole `SecureAD.Next.sln` suite passes.
