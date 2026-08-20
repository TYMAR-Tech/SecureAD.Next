# S-34 — Review where the project is, with the owner

## What this session is for

**Work with the owner to review the current state of the project.** That is the whole brief.

No code. No ledger rows. Nothing is to be built, ported or decided in this session unless the owner
asks for it in the session itself.

## What that means in practice

The owner has not decided what comes next, and this session exists so that he can. The job is to
put the real state of the tree in front of him — plainly, without steering it toward a conclusion —
and to answer what he asks.

Two failure modes to avoid, both of which this repository has produced before:

- **Arriving with a recommendation and reverse-engineering the review to support it.** The point is
  the owner's understanding, not agreement with a plan.
- **Reading documents as though they were the truth.** Slice documents, session briefs and READMEs
  are one person's understanding at one moment. Where a document and the code disagree, verify
  against the definition — the enum, the writer, the query actually sent — and say so. Findings have
  been withdrawn in this tree on contact with the code.

## Where the tree stands, as of this brief

Green at 963 tests. `S-33` is committed at `3a5ff08b`, `S-32` at `8eb399bf`.

The evidence half of the product is close to finished: a run connects to a forest, reads every
partition, reads the Group Policy files on SYSVOL, and seals a bundle that states what it covered
and what it missed. The judgement half has not begun. Reading a bundle back (`C16`–`C28`), deriving
relationships (`D1`–`D9`), evaluating rules (`E16`–`E19`) and reporting findings (`E10`–`E15`) are
all *Not started*, and nearly all are *undecided* — nobody has ruled whether they are ported, rebuilt
or deleted.

**Nothing in the product yet says anything about a customer's directory.**

## Two things the owner was mid-discussion on

Recorded so they are not lost, and **not** to be resumed unless he raises them:

- One rule end to end versus a GUI shell. He chose one rule end to end, then chose to review first.
- Which rule, and whether a noisy-but-true finding is acceptable or a rule must stay silent until it
  can be precise. That second question is his and is unanswered. It surfaced because SEC-064 as
  specified depends on group-membership closure (`D5`, not started) for one of its exclusions.

## Housekeeping, carried and still not blocking

- `docs/decisions/README.md` holds a second, hand-maintained index that stops at `0035`. The real
  index is `docs/DECISIONS.md`, generated and enforced by `DecisionIndexTests`. Delete the hand-kept
  one in favour of a link, or generate it too.
- `next/tools/Read-Bundle.ps1` is untracked and has never been run. It has now survived three
  sessions on that basis. Exercise and commit it, or delete it.
- Untracked and deliberately not committed: `next/ad.lab-20260815-010309/` (a captured bundle),
  `tmp-bundle-query/`, `next/tools/row-a7.txt`, `next/tools/row-a9.txt`.
