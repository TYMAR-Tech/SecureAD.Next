# Session brief - P-85, the Tier 0 control plane

> **Historical brief — completed; not instructions for a new session.** P-85 was settled by
> [decision 0099](../decisions/0099-the-tier-0-control-plane-catalogue.md). The initial control-edge
> slice has since been built and P-150 corrected. The instruction below that `ControlEdge` must
> remain absent applied only to that decision session; it is not a current restriction.
> Read the [current roadmap](../ROADMAP.md) and
> [implemented control-edge boundary](../layers/judgement/the-judgement-store.md#p-150-corrected--catalogue-2-2026-09-06).
> P-145's remaining acceptance checks are still open; the accepted catalogue is not reopened here.

> **Written 2026-09-05.** A brief states the objective and the known ground. It is not authoritative:
> where it disagrees with the code, the code wins and the disagreement is a finding.

## The objective

Settle `P-85` - which principals are the Tier 0 control plane in this product - to the point where
stage 6 can compute expectedness. **This is a decision session, not a building session.** The output
is an accepted decision record and a corrected punch list, not code. `ControlEdge` must stay absent.

## Why this one row now blocks the largest stage in the roadmap

Stage 6 turns permissions into *this principal can take over that object*. Four decisions of
2026-09-05 settled what an edge means, and `0098` is the one that gates on this row: **every control
edge is tagged expected or unexpected, and the screen defaults to unexpected**. An edge is *expected*
when its holder is part of the control plane that already controls the target anyway.

Nothing but `P-85` says what the control plane is. Until it does, every edge is `Unknown`.

**The evidence for why this matters.** The predecessor reported **111,627 control edges and 0
escalation paths** on `ba.ad.lab`, an eight-thousand-object lab. That is not an answer an
administrator can act on. `0098` exists to make the number small; `P-85` decides what gets hidden to
make it small, which is why answering too generously is a wrong answer and not a safe one.

## What has changed about the answer this row must give

**It is no longer a list of group names.** `docs/next/SPEC-stage-6-control-edges.md` section 6 defines
expectedness as a versioned function:

```
Expectedness(holder, target, capability, authorityScope, catalogueVersion)
    -> (Expected | Unexpected | Unknown, ReasonCode)
```

So each catalogue entry must declare **two** scopes, and `AC-S6-14` holds that an entry which does not
declare an unrestricted capability scope does not get one:

- **Authority scope** - where the principal has administrative authority (this domain, the forest).
- **Capability scope** - which capabilities are expected for that role. Unrestricted is legitimate for
  Domain Admins and Enterprise Admins. A delegated or role-specific group that is expected to reset
  passwords must not silently become expected to rewrite every DACL in the domain.

## Read these first, in this order

1. [`docs/WHAT-THE-PRODUCT-IS.md`](../WHAT-THE-PRODUCT-IS.md) - what SecureAD is, and *What a control
   edge means*, which carries the four decisions this session builds on.
2. [`docs/next/SPEC-stage-6-control-edges.md`](SPEC-stage-6-control-edges.md) - sections 6 and 12 in
   particular. **It is a proposal, not a product position**, and its `Q1`-`Q4` are this row's
   sub-questions with the Microsoft research already done.
3. `docs/decisions/0006`, `0095`, `0096`, `0097`, `0098`.
4. The `P-85` row in [`PUNCH-LIST.md`](../PUNCH-LIST.md), which carries the working positions already
   taken and the reasoning behind each.

**Do not trust any of the above over the code.** The last two sessions each found a punch-list row
whose premise was false - `P-70` claimed the product does not judge ownership when `SEC-031`,
`SEC-032` and `SEC-060` were all implemented and scheduled, and `P-71` claimed nothing computes
effective permissions when `EffectiveAccessCalculator` does. Both were caught by opening the code.
Verify every row before putting it to the owner.

## What is already settled, and must not be re-opened

| Settled | Where |
|---|---|
| Account Operators (548) and Print Operators (550) are out - a working position, expected to move before it is locked | `P-85`, owner 2026-08-25 |
| The Domain Controllers group (516) is out; a group of domain controllers is not a domain controller | `P-85`, and `AC-30` |
| Tier 1 means what Microsoft says it means | `WHAT-THE-PRODUCT-IS.md`, owner 2026-09-05 |
| No principal is assigned Tier 1 or Tier 2 until an accepted catalogue defines them | `AC-54` |
| Ownership is an edge only where the owner is not administrative | `0095` |
| Edges are counted at the group and expand to members | `0097` |
| Every edge is stored and tagged; broad principals are never expected | `0098` |

## The sub-questions, with the research already done

Section 12 of the spec carries these with Microsoft citations and a recommendation for each. **Check
each premise against the code before putting it to the owner**, and narrow anything already answered.

- **AD CS and AD FS.** Microsoft's tier model names both as Tier 0 identity services, so *whether*
  they are Tier 0 is settled. What is open is whether the product classifies them automatically - the
  directory names certificate authorities in the Configuration container, and nothing marks an AD FS
  server.
- **Key Admins (526) and Enterprise Key Admins (527).** Microsoft's AD FS documentation states the
  grant these groups receive is Read and Write `msDS-KeyCredentialLink` on descendant user objects.
  **The `CN=Keys` Full Control claim in the punch-list row was not found in Microsoft's published
  documentation** during the 2026-09-05 research pass, and needs the protocol specification or a lab
  observation rather than inference.
- **Read-only Domain Controllers (521), Enterprise Read-only Domain Controllers (498), Replicator
  (552).** Microsoft documents all three as containers of accounts, or as legacy file replication
  support, with no direct user rights - the same shape as the 516 ruling.
- **Customer-declared Tier 0.** Two declarations with opposite risks: declaring an **asset** adds
  something to watch, declaring a **principal** as control plane hides its edges by default.

## How to put a decision to this owner

**He is a security and Active Directory administrator, not a developer.** He knows what the product
must do; he is relying on you for how.

- **Do not ask open questions.** Give two to four concrete options, each with what it looks like on
  screen and what it costs, then recommend one and say why.
- **Check the premise first.** He has corrected several questions across recent sessions and been
  right each time.
- **Make the engineering decisions yourself.** Tooling, test structure, code layout and naming are
  yours, even where a brief says *decide X*.
- **Write the answer down in the same turn he gives it.** Answers go to `WHAT-THE-PRODUCT-IS.md`, and
  anything settled becomes a record in `docs/decisions/` with `Status: Accepted`.

## The safe direction, and why it is not neutral

Under `0098`, a group **left out** of the control plane produces edges tagged unexpected, which are
visible. A group **put in** produces edges tagged expected, which are hidden by default. Being too
cautious adds noise an operator can see and correct; being too generous removes evidence nobody knows
to look for. Microsoft's own anti-pattern list warns that collapsing everything into Tier 0 dilutes
it.

## Definition of done

- `P-85` carries an accepted decision record naming the control-plane set, with **authority scope and
  capability scope for every entry**, or is explicitly narrowed with the parts that remain open.
- Every sub-question is decided, or deferred with a reason and a note saying what it really gates.
- Any row put to the owner was verified against the code first, and anything that had drifted is
  corrected in `PUNCH-LIST.md` with what was found.
- Answers written into `WHAT-THE-PRODUCT-IS.md` in the turn they were given.
- `ControlEdge` still absent; `check-stage-status.ps1` still reports stage 6 not started.
- Full suite green (**3,190 passing** at the end of the 2026-09-05 session); document encoding
  count 14.

## Standing constraints

Never `Get-Content -Raw`. Edit `PUNCH-LIST.md` at line boundaries with no unescaped pipes; a row must
begin with its identifier in the first cell, and an edit that drops the leading cell is caught by
`PunchListIdentifierTests`. New decision records must be added to `docs/DECISIONS.md` by running
`next/tools/Build-DecisionIndex.ps1` rather than by hand. PowerShell commands use `;` rather than
newlines, and anything loading the product's assemblies needs `pwsh`. Full suite:
`cd next; cmd /c "dotnet test SecureAD.Next.sln --nologo > %TEMP%\out.txt 2>&1"`.

## After this row

`P-105` - `Walk` reports the last established root rather than the nearest - is a small building
session that must precede stage 6, because an edge that names the wrong root sends an operator to
remove the wrong membership. The three lab gates in section 13.1 of the spec can run in parallel and
retire the `Unknown`s around ownership, `Self-Membership` and AdminSDHolder.
