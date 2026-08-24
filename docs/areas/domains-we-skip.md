# Domains we deliberately skip

**Area.** How a domain comes to be left out of a run on purpose, how that is distinguished from one
that was missed, and what an operator has to put his name to in order to skip one.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| lets an operator exclude a domain only under an attestation | [`0052`](../decisions/0052-the-domain-is-the-only-unit-of-scope.md), `0049` *(superseded, kept for its reasoning)* |
| asks for a reason from a fixed list, free text, the signed-in account and an authorising name | [`0062`](../decisions/0062-what-an-exclusion-attestation-asks-for.md) |
| stores that attestation in the bundle, so an auditor reading the run later can see it | [`0062`](../decisions/0062-what-an-exclusion-attestation-asks-for.md) |
| re-asks for the attestation every run, and never carries one forward or pre-fills it | [`0059`](../decisions/0059-an-exclusion-is-attested-once-per-run.md) |
| refuses to compare two runs that did not cover the same set of domains | [`0061`](../decisions/0061-runs-of-different-scope-are-not-comparable.md) |
| never renders a domain left out by choice like one it could not reach | [`0063`](../decisions/0063-excluded-never-looks-like-unreachable.md) |
| treats a domain with no candidate controllers as an attested exclusion, never a silent gap | [`0054`](../decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md) |
| treats the domain as the only unit of scope — there is no partial domain | [`0052`](../decisions/0052-the-domain-is-the-only-unit-of-scope.md) |
| reads trusts as a description of a boundary, and never widens a run because of one | [`0051`](../decisions/0051-trusts-describe-a-boundary-and-never-widen-a-run.md) |
| reads the whole forest by default, so skipping is the exception that must be argued for | `0017` |
| never renders an unasked question as a negative answer | [`0002`](../decisions/0002-absent-view-means-degraded-run.md) |

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** A capability whose test does not exist, or does not pass, fails the build — so nothing
here can claim something the product does not do.

**Nothing is built for this area.** That is the honest state, and it was found by the area gate:
every capability first drafted here was already the property of another area, borrowed to make this
page look furnished.

What exists today is the *absence* of a domain, handled where the absence arises — a domain with no
candidate controllers is recorded rather than planned against, in
[how the forest is found](../layers/connect/how-the-forest-is-found.md), and a domain that went unread makes the run
incomplete, in [run identity and coverage](../layers/evidence/run-identity-and-coverage.md). **Neither is a
deliberate exclusion.** Both are the product coping with a domain it could not reach.

The attestation that [`0052`](../decisions/0052-the-domain-is-the-only-unit-of-scope.md) requires —
an operator choosing to leave a reachable domain out, and putting his name to it — has no code, no
test and no screen. **What it asks for is now decided**
([`0062`](../decisions/0062-what-an-exclusion-attestation-asks-for.md)) and none of it is
implemented. Until it is, this page claims nothing.

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This section is the owner's to write.** What follows is a draft list of candidates, offered so
there is something to react to. It is not authoritative and nothing here has been decided.

**Four questions that stood here on 2026-08-16 are now answered** and have moved into *What is
decided*: what the attestation asks for and whether it reaches the bundle
([`0062`](../decisions/0062-what-an-exclusion-attestation-asks-for.md)); whether an exclusion carries
forward ([`0059`](../decisions/0059-an-exclusion-is-attested-once-per-run.md)); whether a run with an
excluded domain may be compared to one without
([`0061`](../decisions/0061-runs-of-different-scope-are-not-comparable.md)); and how an excluded
domain appears beside one with no candidates
([`0063`](../decisions/0063-excluded-never-looks-like-unreachable.md)).

What is still open:

- **Where on the New Audit screen the attestation is asked for.** `0062` settles the content and
  nothing settles the surface.
- **Whether the falsifiable posture is ever tested against the captured data.** `0049` offered to
  demote a run whose claim proved false — *"the domain is empty"* can be checked, *"I lack
  credentials"* cannot. Deferred to ledger row `B11` and still owed.
- **How an excluded domain appears in a report handed to an auditor.**
  [`0062`](../decisions/0062-what-an-exclusion-attestation-asks-for.md) makes this possible without
  deciding it.
- **How exclusions interact with scheduling.**
  [`0059`](../decisions/0059-an-exclusion-is-attested-once-per-run.md) records that a run nobody is
  signed in for cannot attest to anything, and does not resolve it.

---

## Open findings

| | | |
|---|---|---|
| — | none recorded for this area yet | — |
