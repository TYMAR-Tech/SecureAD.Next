# Accepting a finding

**Area.** How an operator says *"yes, we know, and that is fine here"* about a finding, what that
statement carries, where it is kept, and what stops it becoming a way to hide a problem.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| calls this **accepting** a finding, never suppressing or waiving it | [`0066`](../decisions/0066-a-finding-is-called-a-finding.md) |
| requires an acceptance to name exactly one finding, never a pattern | [`0067`](../decisions/0067-an-acceptance-names-one-finding.md) |
| requires a reason, the person accepting, and the time, on every acceptance | [`0067`](../decisions/0067-an-acceptance-names-one-finding.md) |
| keeps an accepted finding visible as a finding, marked rather than removed | [`0067`](../decisions/0067-an-acceptance-names-one-finding.md) |
| makes an acceptance permanent until revoked, and surfaces its age instead of expiring it | [`0067`](../decisions/0067-an-acceptance-names-one-finding.md) |
| stores acceptances beside the evidence and never inside the sealed bundle | [`0067`](../decisions/0067-an-acceptance-names-one-finding.md), `0019` |
| records which run an acceptance came from, so inherited decisions are distinguishable | [`0067`](../decisions/0067-an-acceptance-names-one-finding.md) |
| refuses to apply acceptances from a run that may not be compared to this one | [`0026`](../decisions/0026-one-answer-to-whether-runs-may-be-compared.md), [`0061`](../decisions/0061-runs-of-different-scope-are-not-comparable.md) |
| relies on a finding's identity being stable, or an acceptance silently lapses | [`0023`](../decisions/0023-a-finding-has-a-stable-identity.md) |
| refuses to let a customer lower a severity instead of accepting a finding | [`0066`](../decisions/0066-a-finding-is-called-a-finding.md) |

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** A capability whose test does not exist, or does not pass, fails the build — so nothing
here can claim something the product does not do.

**Nothing in this area is built.** There are no findings to accept yet, so acceptance has no
subject. Everything above is decided and unimplemented.

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This section is the owner's to write.** What follows is a draft list of candidates, offered so
there is something to react to. It is not authoritative and nothing here has been decided.

- **The screen that lists accepted findings, with age visible on it.**
  [`0067`](../decisions/0067-an-acceptance-names-one-finding.md) makes this the control that
  replaces a forced expiry, so without it acceptances are permanent *and* invisible. It is owed and
  undesigned.
- **Who may accept a finding**, and whether the product distinguishes the person who decided from
  the person who typed it, as the exclusion attestation does in
  [`0062`](../decisions/0062-what-an-exclusion-attestation-asks-for.md).
- **How an acceptance is moved between machines or teams**, and what an import is allowed to bring.
- **Whether an accepted finding appears in a report**, greyed, counted, or omitted.
  [`0067`](../decisions/0067-an-acceptance-names-one-finding.md) requires the count to stay honest;
  what a document shows is undecided.
- **What happens to acceptances when a rule changes.**
  [`0024`](../decisions/0024-a-rule-identifier-is-permanent.md) keeps the identifier, but a rule
  whose logic has changed may be raising a different finding under the same name.

---

## Open findings

| | | |
|---|---|---|
| — | none recorded for this area yet | — |
