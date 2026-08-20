# Reports and export

**Area.** What leaves the product as a document: when a report may be produced at all, what formats
it comes in, and what it must say about its own limits. A report is the only part of this product a
customer's auditor will ever see.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| refuses to report at all from a run that did not finish | [`0068`](../decisions/0068-a-finished-run-reports-with-its-gaps-shown.md) |
| reports from a finished run whatever its coverage, with the gaps stated in the document | [`0068`](../decisions/0068-a-finished-run-reports-with-its-gaps-shown.md) |
| sets no threshold above which missing coverage blocks a report | [`0068`](../decisions/0068-a-finished-run-reports-with-its-gaps-shown.md) |
| produces CSV, JSON, HTML and PDF | [`0068`](../decisions/0068-a-finished-run-reports-with-its-gaps-shown.md) |
| produces sealed evidence and never signed evidence, so a report is not proof of origin | [`0030`](../decisions/0030-the-product-produces-sealed-evidence-never-signed.md) |
| names a pattern and never explains one away | [`0015`](../decisions/0015-a-bundle-names-a-pattern-it-never-explains-one-away.md) |
| names the phase that failed when a count cannot be given | [`0004`](../decisions/0004-unknown-counts-name-the-failed-phase.md) |
| keeps an accepted finding countable, so a total stays honest | [`0067`](../decisions/0067-an-acceptance-names-one-finding.md) |

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** A capability whose test does not exist, or does not pass, fails the build — so nothing
here can claim something the product does not do.

**Nothing in this area is built.** No report is generated and no export exists. Everything above is
decided and unimplemented.

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**Who a report is for is deliberately open.** The owner's position on 2026-08-16: *"the reports I
had were done fast and not well thought out"*, and the audience question is deferred to the session
that builds them. [`0068`](../decisions/0068-a-finished-run-reports-with-its-gaps-shown.md) governs
**when** a report may be produced and in what formats, not what it says. **Stop and ask.**

- **Which reports exist, and who reads each.** An auditor's evidence pack, a remediation worklist
  for an AD team and a one-page summary for a manager are three documents with three different
  failure modes.
- **What a report says about accepted findings** — greyed, counted, or omitted.
- **How PDF is produced.** It is the only format that cannot be written with what is already in the
  tree, and picking a means is an engineering decision for the session that builds it.
- **Whether an export can be scoped** — one domain, one rule, one severity — or is always the whole
  run.
- **Whether a report carries the exclusions and their attestations.**
  [`0062`](../decisions/0062-what-an-exclusion-attestation-asks-for.md) puts them in the bundle,
  which makes this possible without deciding it.

---

## Open findings

| | | |
|---|---|---|
| — | none recorded for this area yet | — |
