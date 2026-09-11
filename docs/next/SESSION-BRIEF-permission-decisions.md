# Session brief — the permission decisions, before stage 6

> **Historical brief — completed; not instructions for a new session.** Decisions `0095`–`0098`
> settled this session's permission questions. The initial control-edge slice has since been built
> and P-150 corrected. The original objectives, counts and instruction to keep `ControlEdge` absent
> below describe the earlier decision-only session; do not execute them now or reopen its decisions.
> Use the [current roadmap](../ROADMAP.md), [accepted decisions](../DECISIONS.md) and
> implemented control-edge boundary.

> **Written 2026-09-05.** A brief states the objective and the known ground. It is not authoritative:
> where it disagrees with the code, the code wins and the disagreement is a finding.

## The objective

Settle the decisions that stage 6 cannot be built without, and record them. **This is a decision
session, not a building session.** The output is accepted decisions and a corrected punch list, not
a new screen.

Stage 6 — control edges — is *turn permissions into "this principal can take over that object"*,
and `ROADMAP.md` calls it the largest single piece and what makes an AD audit tool worth having.
Four punch-list rows (`P-70`–`P-73`) are recorded as needing an owner ruling, and every one of them
decides what a control edge **means** rather than how it is computed. Building stage 6 first would
mean choosing all four by accident.

## Correct this before you start

**`P-70` says the product does not judge ownership. That may no longer be true, and you must check
before asking the owner about it.**

`SecureAD.Judgement.BroadPrincipalCanTakeOverObject` exists, is scheduled, and already reasons about
`WriteOwner`, `WriteDacl` and `GenericAll` — and consults the forest's owner-rights setting to
decide whether a `WriteOwner` grant is takeover-class at all. `ObjectOwnershipEvidence` and
`ObjectTakeoverEvidence` are both typed evidence carriers with `IsComplete` vouchers, added
2026-09-05.

So *some* of what `P-70` asks may be answered in code. **Read those three types before you form a
picture of what exists.** The last session was told the product had "no screen that shows findings
to anybody"; that claim was false, had reached `WHAT-THE-PRODUCT-IS.md`, and was corrected only
because someone opened `AssetsViewModel` instead of trusting the roadmap. The punch list is prose
and prose is discussion, not truth.

If `P-70` is partly overtaken, **narrow the question before putting it to the owner.** Asking him to
rule on something already built wastes the one resource this project is short of.

## What is being decided, and why each one gates stage 6

| Row | The question | Why stage 6 cannot proceed without it |
|---|---|---|
| `P-70` | Whether the product judges ownership at all | An owner implicitly holds Modify Permissions and can grant himself full control. If owning an object is not an edge, the graph is missing the most direct takeover there is |
| `P-71` | How effective permissions are presented — what a principal can *actually* do once denies, inheritance and group membership are taken together | A control edge **is** an effective-permission claim. Deciding how it is presented after building it means rebuilding it |
| `P-72` | How a permission held through a group is attributed — to the group, to the member, or to both | Decides the shape of the graph and, as the row says, *affects every count an operator reads* |
| `P-73` | What the product says about a permission that is dangerous but expected | Without it every edge from every administrator is a finding, and the screen is unusable |

**`P-73` is the one to think hardest about, and the predecessor is the evidence.** Its dashboard
reported **111,627 control edges** and **0 escalation paths** on `ba.ad.lab` — a lab forest of about
eight thousand objects. A number that large is not an answer an administrator can act on; it is a
number he learns to scroll past. `0006` keeps Tier 0 and expected-administrator as separate sets,
and what an operator sees where the two meet is undrawn. Decide it now and stage 6 has a target;
decide it later and stage 6 has a backlog.

## Others that may need an answer first — establish, do not assume

These are **candidates**. Part of the session's job is deciding which genuinely gate stage 6 and
which can wait, and saying so rather than sweeping them all in.

- **`P-85` — which groups count as Tier 0 seeds in this product.** Coupled to `P-73`: *dangerous but
  expected* cannot be defined without knowing what the control plane is. The row warns that
  answering too generously is a wrong answer and not a safe one, citing Microsoft's own anti-pattern
  list on diluting Tier 0. Includes three sub-questions: what Full Control over `CN=Keys` confers,
  whether RODC/Enterprise RODC/Replicator *groups* confer identity-plane control, and whether a
  customer may declare additional Tier 0 assets.
- **`P-105` — which established root wins a membership basis.** `Walk` reports the *last* root
  processed, not the nearest, so three accounts directly in **Enterprise Admins** on `ad.lab` are
  each reported under **BUILTIN\Administrators**. Both statements are true; they tell an operator to
  do different things, and the remediation is to remove the account from Enterprise Admins. An edge
  that names the wrong root sends someone to fix the wrong thing.
- **`P-107` — whether one general Microsoft sentence settles four `Unverified` propagation claims in
  `0089`.** Concrete effect on `ad.lab`: three domain controllers now reported `Unknown` would
  become `Protected`. The row asks for the protocol specification or a controlled lab test rather
  than settling it from the sentence alone.
- **`P-67` — whether `RuleDefinition.IsComplete` is a constant wearing a computation's clothes.**
  Cheap, and it is a failure-class-1 shape sitting under a gate that looks like it verifies it. The
  row is explicit that the gate cannot answer this and does not claim to, and that the answer must
  **not** be inferred from the rule set as it stands.

## How to put a decision to this owner

**He is a security and Active Directory administrator, not a developer.** He knows what the product
must do; he is relying on you for how.

- **Do not ask open questions.** *"How should effective permissions be presented?"* is not answerable
  by anyone who has not already designed it. Present two to four concrete options, each with what it
  would look like on screen and what it costs — then recommend one and say why.
- **Check the premise first.** He corrected two of the last session's three questions, and was right
  both times: he asked when a domain could be *partly read* (it cannot — capture is fail-fast) and
  pointed out that failed runs never finish capture so cannot land anywhere. A question resting on a
  false premise wastes his time and produces a decision about nothing.
- **Reserve questions for what only he can answer.** What the product should say, what an
  administrator would expect, which risk is acceptable, what to prioritise. Tooling, test structure
  and code layout are yours.
- **Write the answer down in the same turn he gives it.** A question he has already answered is a
  defect in this repository, not a lapse of memory. Answers go to `WHAT-THE-PRODUCT-IS.md`, and
  anything settled becomes a record in `docs/decisions/` with `Status: Accepted` — those two are the
  only places that state the product's position.

## What this session must not do

- **Do not build stage 6.** The witness is `ControlEdge` and it must stay absent; `check-stage-status.ps1`
  asserts both directions, so a half-built type would move the stage row and make the roadmap lie.
- **Do not answer a decision row on the owner's behalf** because the answer seems obvious. `P-85`
  warns that the generous answer is the wrong one, not the safe one.
- **Do not close a row without a Decision: line.** A finding without one is discussion, however
  well argued.
- **Do not trust a punch-list row's description.** Several are months old. Verify each against the
  code before it reaches him — `P-70` is already suspect, and `P-23` is recorded as blocked on an
  entry point that now exists.

## Where things are

| Path | What it is |
|---|---|
| `docs/PUNCH-LIST.md` | the rows; **edit at line boundaries, no unescaped pipes** |
| `docs/decisions/` | where an accepted answer lands |
| `docs/WHAT-THE-PRODUCT-IS.md` | where an answered question is recorded the same turn |
| `next/src/SecureAD.Judgement/BroadPrincipalCanTakeOverObject.cs` | what already reasons about takeover |
| `next/src/SecureAD.Evidence/Findings/ObjectOwnershipEvidence.cs` | typed ownership evidence |
| `next/src/SecureAD.Kernel/Security/` | `DangerousPermissionClassifier`, `PermissionAssessment` |
| `next/src/SecureAD.Derivation/` | `Walk`, membership bases — `P-105`'s subject |
| `docs/decisions/0006`, `0077`, `0082`, `0089` | cited by the rows above |
| docs/layers/judgement/ | how judging works today |

**A lab bundle with real data**: `C:\Users\ba.admin\SecureADRuns\ad.lab-20260905-035415` — three
domains, 8,383 objects, 2,071 users, 11 computers, 2,163 groups, 174 OUs, 15 GPOs, all three domains
read in full over sealed connections. It contains **planted positives**;
`Set-LabOwnershipAndTakeover.ps1 -Remove` clears them. The dashboard built 2026-09-05 shows these
figures and they were checked against the live directory by hand.

**The predecessor is on disk** at `C:\Users\ba.admin\source\repos\razamus\SecureAD`. The owner's
instruction stands: *treat this as a source not an answer, look at what it did but also consider if
there is a better way.* Its control-edge counts are the cautionary evidence for `P-73`.

## How this repository expects work to be done

- **A check that passes while measuring nothing is failure class 1**, and it has happened three
  times. Every gate carries a self-test.
- **A green test proves nothing until it has been watched failing.** Mutate, observe, revert — one at
  a time. The last session did this three times and each mutation caught something.
- **Ask what a set of checks is anchored to**, not only whether each one is sound. `F-S44-2` was a
  closed loop of sound checks anchored to the wrong reference.
- **Standing constraints**: never `Get-Content -Raw`; the document encoding count must stay **14**;
  edit `PUNCH-LIST.md` at line boundaries with no unescaped pipes; delete scratch scripts;
  PowerShell commands use `;` rather than newlines, and anything loading the product's assemblies
  needs `pwsh`, not Windows PowerShell.
- **Housekeeping owed**: nine untracked scratch scripts are sitting in `next/tools`
  (`tmp-*.ps1`, `add-f4510.ps1`, `add-f4511.ps1`, `fix-punchlist.ps1`). They are from earlier
  sessions and were left rather than deleted because untracked files cannot be recovered. Ask, then
  clear them.
- Full suite: `cd next; cmd /c "dotnet test SecureAD.Next.sln --nologo > %TEMP%\out.txt 2>&1"`.
  Currently **3,190 passing**.

## Definition of done

- `P-70`–`P-73` each carry either an accepted decision record or an explicit **Decision:** line, or
  are shown to be already answered in code and closed with the evidence cited.
- Every row put to the owner was verified against the code first, and any that had drifted is
  corrected in `PUNCH-LIST.md` with what was found.
- The candidates above are each either decided, or explicitly deferred with a reason and a note
  saying which stage they really gate.
- Answers written into `docs/WHAT-THE-PRODUCT-IS.md` in the turn they were given.
- `ControlEdge` still absent; `check-stage-status.ps1` still reports stage 6 not started.
- Full suite green; encoding count 14.
