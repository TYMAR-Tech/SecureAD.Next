# What the product is

This file exists because the same questions were asked of the owner four times in one session, and
the answers had been given before. Nothing else in this repository says what SecureAD *is* — the
instructions say how to work, the layer documents say what the code does, the decision records
settle particular questions. A session that reads all three still does not know the shape of the
product, and asks.

**This is orientation, not authority.** Nothing here states the product's position; only a record in
`docs/decisions/` with `Status: Accepted` does that. Where this file and a decision record disagree,
the record wins and this file is wrong.

## The shape

**SecureAD is a GUI application.** The operator starts an audit, waits while it captures and
analyses, then clicks around what it found — findings, LAPS status, objects, permissions. That
clicking-around is the product. Everything else serves it.

**The command line is a capture tool, not a second product.** `securead.exe` exists so a capture can
be left running overnight without the application open. It captures; it does not analyse and it does
not show anything. Do not propose adding analysis verbs to it.

**The three phases the operator sees are capture, analysis, then reading.** They are sequential and
they do not overlap — [`0072`](decisions/0072-analysis-and-capture-do-not-run-at-the-same-time.md)
settles that analysis never runs while a capture does.

## What the predecessor did

There is an old application. It worked, the owner ran it, and it is the reason this rebuild knows
what it is aiming at. **Its inventory and component map were archived and are deliberately not in
this repository** — the owner keeps the old repository and consults it himself. Do not ask for it.

What follows is what the owner has told this repository about it, written down so it is not asked
for again. It is history, not a specification.

### Analysis was a pipeline, not one pass

`DerivedAnalysisPipeline` ran eleven named phases in a fixed order, each committing before the next
began:

> analyze → create views → GUID map → delegation bundle matches → group expansion → control edges →
> escalation paths → asset tier → findings → backfill finding principals → chokepoints

Three properties matter for anything built here:

- **Each phase was a distinct pass with its own materialised output.** Group expansion wrote a
  membership closure; control edges read that closure and wrote edges; escalation paths read those
  edges. Dependent stages, not one pass offering every object to every rule.
- **Findings ran late,** after the graph existed, so a rule could ask "is this principal Tier 0?"
  and get an answer.
- **Each phase was independently fault-tolerant.** A failure left later phases running and the run
  ended degraded.

**This differs from what is built here today.** `JudgingRun` streams the bundle once and offers each
object to every scheduled rule. That is right for rules that read one object's attributes — which is
all SEC-010 and SEC-011 do — and it cannot express a rule that needs group membership already
resolved. Graph rules will need a derived stage in front of the streaming pass. That is a known
shape, not a defect in the current design.

### Where the indexes were

The old application carried 55 indexes and roughly forty were on derived tables — data analysis
produced, not data the directory gave. The concentration says where the pain was:

| Table | Indexes | What that implies |
|---|---|---|
| `fact_control_edge` | 7, including a composite on target, deny state and type | the hot table: queried by source, by target, by type, by deny state |
| `dim_object` | 7 | domain, class, SID, DN, reversed DN, owner, sAMAccountName |
| `fact_group_membership_direct` / `_closure` | 4 | both directions, both tables |
| `fact_delegation_bundle_match` | 3 | by object, by trustee, by bundle |
| `fact_ace` | 2 | by trustee, by object-type GUID |

Its own performance instrumentation named what was watched on open: binding the objects tab,
building the tree, binding security grids, counting control edges, counting by severity, building
the coverage summary. So the slow things were **opening a bundle and binding grids, building the
tree, and dashboard aggregates.**

**Do not port these.** The old application materialised ACLs per object; this one deduplicates
descriptors by hash, so its ACE pressure may not transfer at all. This is where to look first, not
what to build. Nothing here is measured against this schema.

## What is built here, as of 2026-08-26

Capture works and is reachable from both the shell and the command line. Evidence is sealed and can
be read back. Judging works — two rules, confirmed against a real forest — but **is reachable only
from `next/tools/judge-bundle.ps1`, a developer script.** The application cannot open a bundle at
all, which is why the Dashboard and Findings tabs are placeholders.

[`docs/ROADMAP.md`](ROADMAP.md) is the live plan and says what is owed. This file says what the
product is; the roadmap says how far along it is. When they disagree the roadmap is newer.
