# How privilege escalates

**Area.** How the product works out that one principal can reach another's privileges through a
chain of permissions and memberships, and what it says about such a chain. A single permission is
rarely the whole story; the chain is.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| keeps Tier 0 and expected-administrator as two separate sets | [`0006`](../decisions/0006-tier-0-and-expected-admin-are-separate-sets.md) |
| treats nothing inherited as definitive | `0033` |
| holds the rule catalogue as data and the rule logic as code | [`0010`](../decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md) |
| gives a finding a stable identity, whatever produced it | [`0023`](../decisions/0023-a-finding-has-a-stable-identity.md) |
| never lets a run appear clean while carrying unknowns | [`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) |

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** A capability whose test does not exist, or does not pass, fails the build — so nothing
here can claim something the product does not do.

**Nothing in this area is built.** No chain is computed, no path is stored, and no rule reads one.
The capture side supplies the raw material — memberships, permissions, delegation attributes — and
nothing consumes it yet.

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This area has not been discussed.** The owner flagged it on 2026-08-16 as needing deeper
discussion of its own, and nothing below has been decided. **The right move on reaching this area is
to stop and ask**, not to infer a design from the predecessor, from the reference inventory, or from
the shape of the capture data.

The agent's questions, offered only so there is something to react to:

- **What counts as a step in a chain**, and what does not.
- **How far a chain is followed**, and what is said about one that was cut short. The predecessor
  limited paths to five hops and showed *"retained representative evidence paths"* — a phrase that
  states both a limit and a selection, and neither has been discussed here.
- **How the product states how well it knows a chain.** The predecessor carried an *Evidence Level*
  of `Graph Reachability`; the honesty in that is worth keeping and its shape is undecided.
- **Whether a chain is a finding, several findings, or the context around one.**
- **How a chain that passes through an accepted finding is treated.**

---

## Open findings

| | | |
|---|---|---|
| `F-0006-1` | `0006` excluded Account, Server, Print and Backup Operators from Tier 0, reasoning that escalation paths *from* them are worth reporting. Microsoft names Backup Operators and Server Operators among its Tier 0 built-in groups, and a path leaving a group was never a reason to refuse a path arriving at it. The exclusion was inherited from the predecessor, where `HighValueTargets.cs` carries the same reasoning in a comment, and it passed owner review unread. Corrected 2026-08-22, with Cert Publishers (517) added at the same time. | **closed** |
