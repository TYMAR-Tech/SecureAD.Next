# What we call a finding

**Area.** What the product produces when a rule matches: what it is called, what identifies it, what
it carries, and how severe it is said to be. This is the vocabulary every screen and every report
inherits.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| calls the thing it finds a **finding**, on every screen and in every report | [`0066`](../decisions/0066-a-finding-is-called-a-finding.md) |
| fixes a finding's severity by its rule card, and lets no customer change it | [`0066`](../decisions/0066-a-finding-is-called-a-finding.md) |
| gives a finding a stable identity, so the same finding is recognisable across runs | [`0023`](../decisions/0023-a-finding-has-a-stable-identity.md) |
| never reuses a rule identifier, whatever happens to the rule | [`0024`](../decisions/0024-a-rule-identifier-is-permanent.md) |
| holds the rule catalogue as data and the rule logic as code | [`0010`](../decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md) |
| names a pattern in a bundle and never explains one away | [`0015`](../decisions/0015-a-bundle-names-a-pattern-it-never-explains-one-away.md) |
| never lets a finding appear clean while its coverage carried unknowns | [`0056`](../decisions/0056-the-visual-language-encodes-three-states.md) |
| rates a privileged variant of a rule above its base, lets both findings stand, and inherits no acceptance between them | [`0079`](../decisions/0079-a-privileged-variant-of-a-rule-escalates.md) |

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** A capability whose test does not exist, or does not pass, fails the build — so nothing
here can claim something the product does not do.

**Nothing in this area is built.** Sixty-two rule cards exist in `docs/rules/`, and twenty-five of
them are referenced by capture code as the reason an attribute is read. No rule is evaluated, no
finding is produced, and no finding is stored. This is expected rather than a gap:
[`0045`](../decisions/0045-the-shell-is-built-before-the-judgement-half.md) decided the shell is
built before the judgement half.

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This section is the owner's to write.** What follows is a draft list of candidates, offered so
there is something to react to. It is not authoritative and nothing here has been decided.

- **What a finding carries.** The predecessor's had a subject, a target, a severity, a rule, a
  human-readable detail, per-finding coverage completeness, and a context blob. Which of those this
  product keeps is undecided.
- **What the severity scale is.** [`0066`](../decisions/0066-a-finding-is-called-a-finding.md) fixes
  severity to the rule card without saying what values exist or what they mean.
- **Whether a finding records how well it was established**, the way the predecessor's escalation
  paths carried an evidence level.
- **Whether a customer may tune the rule catalogue at all** — disable a rule, or add one. Raised in
  `0066` and explicitly left open.
- **How a finding whose coverage was incomplete is presented**, as distinct from one whose coverage
  was whole.

---

## Open findings

| | | |
|---|---|---|
| — | none recorded for this area yet | — |
