# 0051 - Trusts describe a boundary; they never widen a run

Date: 2026-08-14
Status: Accepted

## Context

Ledger row `A7` - forest topology discovery - is built and has no decision record. The half of it
that reads trusts was carried across from the predecessor without being examined, and three things
about it are wrong.

**Trusts are not captured.** `B21` copies them from the `ForestTopology` object discovery already
built, so the trust rows in a sealed bundle never came through the capture path and have no security
descriptor behind them. They are discovery metadata wearing the clothes of evidence.

**`trustAttributes` is read and discarded.** The predecessor pulls it, uses it to compute one
boolean about transitivity, and keeps nothing else. Every security-bearing bit in that field is
thrown away - including the one that says whether SID filtering is switched on.

**A disabled trust reports as bidirectional.** `ClassifyTrustDirection` maps 1, 2 and 3 and sends
everything else to `Bidirectional` as a "safe default". `trustDirection` of 0 means *disabled*, so a
trust that is switched off is currently described as fully two-way.

There is also a question the owner raised from real use: in the predecessor he had to untick domains
before a run because of one-way trusts. Those domains turned out to be in *other forests*. The
enumeration was reaching outside the forest being audited and offering the result as scope, and a
checkbox was undoing it by hand.

## Decision

**A trust is an edge that leaves the captured graph. The forest is the unit of capture, and a trust
is evidence about its boundary rather than a doorway to walk through.**

**Trusts never influence scope.** The domains a run reads come from the `crossRef` objects in the
configuration partition, which describe one forest. Trust enumeration contributes nothing to that
set and is never consulted about it. **A one-way trust therefore cannot shrink a run**, because the
only trusts that can be one-way are trusts to something outside the forest, and nothing outside the
forest was ever in scope. The predecessor needed a checkbox to undo an over-collection; there is
nothing here to undo.

**No foreign forest is enumerated, ever.** A trusted forest has its own configuration partition and
its own audit. If a customer wants it audited, that is a second run and a second bundle.

**`trustedDomain` objects are captured, not copied.** They live in `CN=System` inside a domain
naming context the run already reads, they carry a security descriptor, and they are already
classified as Tier 0. Capturing them makes the trust graph evidence with the same provenance as
everything else in the bundle, and closes the gap `B21` left.

**`trustAttributes` is preserved whole and its bits are reported.** The severe findings about a
trust need nothing from the far side of it and are measurable entirely from within the forest being
audited:

- **SID filtering absent on an external trust** - an administrator on the far side can mint a
  security identifier from this forest and authenticate as anyone in it.
- **A forest trust marked to be treated as external**, which relaxes the same protection
  deliberately.
- **Selective authentication absent**, so every principal across the boundary may authenticate
  everywhere within it.
- **Weak trust cryptography**, from the supported encryption types.

**Foreign Security Principals are the other half and they are captured.** Objects under
`CN=ForeignSecurityPrincipals` carry a foreign security identifier, live inside a domain this run
reads, and are where a principal from across a boundary actually holds group membership and rights
here. Joined to `securityIdentifier` on each `trustedDomain`, they turn *"a trust exists"* into
*"fourteen principals from across this trust hold privilege here, and three of them are Tier 0"* -
which is the finding an auditor acts on, obtained without a single read outside the forest.

**An unrecognised trust type or direction is preserved and reported as unrecognised.** It is never
coerced to a familiar value. `trustDirection` of 0 is **disabled**, and a disabled trust with
foreign principals still holding privilege is itself worth reporting. Microsoft has added trust
shapes over time and will add more; a product that quietly maps an unknown one onto a known one
misdescribes a customer's boundary while looking healthy, which is what
[`0002`](0002-absent-view-means-degraded-run.md) forbids.

**A downlevel Windows NT trust is a finding on presence alone.** The partner is a Windows domain not
running Active Directory. In a forest audited today that is either a genuinely forgotten liability
or a misconfigured object, and both are worth a sentence.

**A realm trust to an MIT Kerberos KDC is not.** These are legitimate and current, and reporting
their existence as a problem would be noise. They are flagged on their properties instead - stale
encryption support, unexpected transitivity, and an inbound direction that lets a non-Windows key
distribution centre assert principals into the forest. **A realm has no SID-filtering concept, so
the quarantine analysis is not applied to one and is not reported as though it were.**

**Trusts are not shown at preflight.** They are noise at the moment an operator is deciding whether
a run can proceed, and showing them there invites the misreading that they are a scope choice. They
belong in the bundle and in what is reported from it.

## Consequences

The product gains its highest-severity findings about forest boundaries without ever reading across
one. A trust with SID filtering disabled is close to the most serious thing an Active Directory
audit can report, and it is visible from inside.

`dim_trust` stops being discovery output and becomes capture output, which is a change to where the
data comes from rather than to what it says.

The predecessor's domain-deselection-for-trust-reasons disappears as a need. It was compensating for
an enumeration that reached too far, and the enumeration no longer does.

A trust this product does not understand is reported as not understood, with its raw values shown.
That is less tidy than a confident wrong answer and it is the only honest option.

Nothing may restate this record. Rows, comments and notes cite `0051`.
