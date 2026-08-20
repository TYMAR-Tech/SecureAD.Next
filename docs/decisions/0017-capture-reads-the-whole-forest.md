# 0017 - Capture reads the whole forest; scope is applied to reading, never to evidence

*Its unmeasured-cost claim, and the breadth of "whole forest", corrected by 0034.*

Date: 2026-08-10
Status: Superseded by 0052 *(see record)*. Its rule is carried forward with one change: the domain
is now a unit an operator may leave out, which this record's absolute wording - *"nothing an
operator can set makes a run smaller"* - refused. Everything below the domain is still read whole,
for the reasons set out here. Read this for the reasoning; read
[0052](0052-the-domain-is-the-only-unit-of-scope.md) for the rule.

*Signed bundle* and *scoped signature* were corrected to *sealed* below, per
[0030](0030-the-product-produces-sealed-evidence-never-signed.md).

## Context

The previous product let an operator exclude organisational units from capture. The filter was
applied at three sites and refused one container outright, dropping `CN=Managed Service Accounts`
from the exclusion list at construction - silently, so an operator who asked to exclude it believed
he had.

The feature came from a real customer: an enormous container held for legal retention, reviewed at
the time and judged to hold nothing of security relevance. That judgement was reasonable and it is
the shape of the problem. Security relevance is not a property of a container; it is a property of
a container **on a date**. Objects accumulate, a service account is created inside, control of the
container is delegated to whoever runs the retention tooling. Nothing about the original decision
was wrong. It expired, quietly, and nobody re-made it.

An exclusion at capture is also porous, and porous in ways that make the result worse rather than
merely smaller:

- A dangerous permission **held by** a principal inside the excluded container is still captured,
  because it sits on the target object. The holder is not, so the report names an unresolvable
  identifier. The risk is visible and its owner is not.
- Inherited entries reach into the excluded container, so any count of what a permission reaches is
  understated by exactly the size of the exclusion, with nothing saying so.
- A group outside the container can hold members inside it, which is why the filter needed a third
  application site at all.
- The one thing genuinely hidden is the delegation set **on** the excluded container - which is
  precisely what an auditor would want to know about it.

Two further facts settled the direction. The protection the filter offered was by distinguished
name, which is the wrong axis: a group managed service account can be created in any container, so
a guard naming one well-known location defends a place rather than a kind of thing. And the
product's own suggested exclusions included `CN=Keys`, which Microsoft's domain preparation creates
as *"default container for key credential objects"* - authentication material, and the container
whose permissions decide who can write it.

Meanwhile capture is the cheap half of a run. It is paged at up to a thousand objects per request
and bounded by a per-controller rate limit, so a forest of millions of objects is minutes of
network-bound work. Derived analysis - control edges from every access control entry, group
expansion, escalation-path traversal - is the part that takes the time, and it is combinatorial
rather than linear.

A read-permission problem, which was a second argument for exclusions, has a deployment answer:
run from a privileged administrative workstation with rights sufficient to read the directory.

## Decision

**Capture reads the whole forest**, except the noise classes named in
[`0034`](0034-capture-excludes-a-shipped-noise-list.md). There is no operator-configurable
exclusion of any part of the directory from capture: the noise list ships with the product, may
hold only classes that can be neither a hop nor a principal, and the one switch an operator has
reads *more* than the default rather than less. Nothing an operator can set makes a run smaller.

**Analysis is performed over everything captured.** In particular the control graph and escalation
paths are built complete, because a path that passes *through* a container a customer does not care
about, to reach one they do, is a real path.

**Scope is applied at the reading layer**, to grids, dashboard figures and exported documents alike,
and it lives in the sidecar beside the notes, suppressions and tier overrides that
[`0015`](0015-a-bundle-names-a-pattern-it-never-explains-one-away.md) already places there. It is
the customer's annotation about their organisation, not a claim by the product.

**The sealed bundle is never scoped.** A scoped bundle would let a customer produce, by ticking a
box, an artefact that carries this product's name and is clean by omission. That is the failure
[`0003`](0003-refuse-to-reanalyse-an-incomplete-capture.md) refuses in one form and
[`0015`](0015-a-bundle-names-a-pattern-it-never-explains-one-away.md) refuses in another.

**A figure that has been scoped says so**, and can name what was left out in one step. A bare count
that has quietly had a subtree removed from it is the same defect as a count that cannot say whether
anyone looked.

**A container that cannot be read is a coverage failure, not a scope.** The run is degraded and says
which part it could not reach. It is never presented as a decision the customer made.

## Consequences

Every bundle is a complete record of the forest as it stood. Re-analysis under
[`0003`](0003-refuse-to-reanalyse-an-incomplete-capture.md) becomes trivially satisfiable, because
there is no longer a category of capture that is complete-as-configured but incomplete in fact.

Changing one's mind stops being expensive. A scope is a filter over data already held, so it applies
and un-applies immediately, with no directory access and no new capture window. Under the previous
design, reconsidering an exclusion meant recapturing the forest.

A scope is offered **after** a run rather than demanded before one. The evidence-based
recommendation the previous product already computed - containers with many objects and no findings
- becomes the way a customer is offered a scope, which is a far safer thing to be wrong about when
it governs a report rather than the evidence.

Escalation paths through a scoped container to an unscoped target are found and reported, naming the
scoped object as a hop. This was not possible before and is the clearest single gain.

**This decision costs capture and analysis time, and the amount is now measured.** Whatever an
excluded region would have saved is otherwise spent. For the customer that motivated the original
feature that is several hundred thousand objects. A later measurement put a single vendor class at
two thirds of every object in one forest, which is what
[`0034`](0034-capture-excludes-a-shipped-noise-list.md) responds to: the whole-forest rule holds,
and bulk with no security meaning is named and never read. The remaining cost lands in the same
place as the deferred question about capture concurrency, and the same measured baseline settles
both.

Scope saves no run time. Building the graph completely is required for correctness, and the per
object work that could be skipped is the inexpensive part. Scope is a readability feature; making a
run finish sooner is a separate problem in the derived-analysis branch.

A customer forwarding a bundle to an auditor or insurer is forwarding the complete analysis,
including findings they chose not to see. That is correct and it will surprise someone, so the
product says so plainly rather than leaving it to be discovered.

Ledger row B3 is deleted rather than rebuilt. The exclusion filter, the protected-container guard,
the exclusion attestation, and one meaning of *in forest but not captured* all go with it. What is
salvaged is the concept of a declared scope, which belongs to the reading layer, and the
recommendation service, which changes what it recommends rather than how it works.
