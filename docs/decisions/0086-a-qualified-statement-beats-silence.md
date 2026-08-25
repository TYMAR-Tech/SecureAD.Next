# 0086 - A qualified statement beats silence, except where completeness is claimed

Date: 2026-08-25
Status: Accepted

Sits under [0066](0066-a-finding-is-called-a-finding.md), which fixes severity on the rule card, and
beside [0002](0002-absent-view-means-degraded-run.md), which refuses to let a gap pass as a clean
result. Generalises `AC-97` from one rule to the product.

## Context

The judgement specification is built almost entirely around ways the product could state something
false, and it is right to be. But the instrument it reaches for most often is refusal, and refusal
has a cost nobody has priced.

`AC-96` rules that a `ResearchBlocked` capability "yields no established edge at any confidence,
never enters `G_definite`, and is never promoted by ordering". `AC-26` and `AC-64` block SDProp
traversal through distribution groups and primary-group membership until Microsoft evidence exists.
Each of those is correct as written. Taken together as a habit, they point somewhere unintended:

**a product that says less than its predecessor, about a directory that is no safer.**

Some of what the predecessor reported was unproven and some of it was right. Removing all of it
raises the standard of what the product asserts and lowers what an administrator learns. An audit
tool that will not speak is not more accurate. It is only easier to defend.

**The owner's test, stated 2026-08-25:** findings must "generate something that can really be used
to help an organization improve their Active Directory". Silence fails that test in a way an honest
qualification does not.

The specification already has the better instrument and already uses it once. `AC-97`:

> A principal with an observed candidate path to a protected group through a research-gated edge
> evaluates `Unknown` with the naming reason, not `NotProtected`.

That is the shape. The gated edge does not become an established fact, and the principal does not
get reported clean either. The uncertainty is named and surfaced.

## Decision

**Where the product cannot establish something, it says so with what it does know, rather than
saying nothing.**

`Conditional`, `Potential`, `Unknown`, confidence levels and `UncertaintyRegion` exist for this and
are the default response to missing or gated evidence. A gated capability produces no **established**
edge - `AC-96` stands unchanged - but the principal it touches is never quietly reported clean.
`AC-97`'s rule is the general rule, not a special case of protected-principal derivation.

**Silence is reserved for the completeness claim.**

Where the product asserts that a remediation is sufficient - that an action lies on every route, that
a fix is complete, that a principal is `NotReachable` - an unproven answer is withheld rather than
qualified. `AC-16`, `AC-21`, `AC-22`, `AC-33` and `AC-99` are untouched by this record. That is the
one place where a qualified statement is worse than none, because an administrator acts on it and
stops looking.

**The test for any gate is what an administrator learns, not what the product can defend.**

Before a rule refuses to report something, ask whether a reader would be better served by a named
uncertainty. If yes, that is the answer. *We could not establish this, here is what we saw and what
we could not check* helps someone. An empty screen does not.

## Consequences

- Rules must be able to emit a finding whose evaluation is `Indeterminate` with a stated reason, and
  the shell must have somewhere to show it. A finding that says *we could not tell* is a finding.
- Coverage and uncertainty become customer-visible surfaces rather than diagnostics. The predecessor
  already carried a `Coverage` column on its findings grid; that is continuity, not new work.
- `AC-26` and `AC-64` stay blocked as established edges, and the principals they touch must still
  surface as `Unknown` with the gate named. Blocked is not invisible.
- This makes the product noisier. That is accepted: a named uncertainty an administrator can dismiss
  is a better failure than a clean screen he cannot question.

## What this does not license

It is not permission to guess. An unestablished capability is never reported as established, never
enters the definite graph, and never carries a confidence it has not earned. The choice this record
makes is between **naming an uncertainty** and **staying silent** - never between establishing
something and inferring it.
