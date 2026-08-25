# 0008 - Live directory verification is removed from the product

Date: 2026-08-09
Status: Accepted; the claim that capture reads the schema partition is corrected by [0014](0014-capture-reads-the-schema-partition.md)

Supersedes decisions 2, 3 and 4 of the archived product-identity review.

## Context

The product is a forest-wide audit that produces point-in-time evidence. Alongside that it grew a
surface that queried a domain controller during a session: effective access for one object, a
delegation report for one OU, an ACL comparison for one distinguished name, a browsable directory
tree.

An earlier decision kept that surface, on the grounds that verifying stored evidence against the
directory is part of auditing it. Tracing it end to end does not support the grounds. Every
operation in it takes a single distinguished name, and there is no forest-wide live operation
anywhere in the product. An auditor holding four thousand findings cannot ask "which of these are
still true" through it; they can ask about one object, four thousand times.

The question it was built to answer is real, and is already answered better: capture the forest
again and compare the two runs. That is forest-wide, it is evidence rather than a screen, and it
exists. The live surface also never states the age of what it contradicts, which is the one fact
that decides whether a disagreement means anything.

## Decision

The product does not read from a directory except to capture a run.

Live effective access, live inheritance, live ACL comparison, live delegation reporting, the
directory tree and the Inspect view are not part of the product. Verification of stored evidence is
performed by capturing again and comparing, which is the only operation that works at the scale the
product audits at.

Capture is unaffected. It reads the directory, including the schema partition, and is the sole
reason the product connects at all.

## Consequences

An auditor cannot ask about one object in real time. That is accepted: a question about one object
right now is an operator's question, which this tool has already declined to serve.

Re-capture and compare becomes load-bearing rather than supplementary, so any weakness in comparison
is now a weakness in the only verification path.

Provenance stops being a live-result problem and becomes an artefact problem only.

Reintroducing live reads requires a new record, which must first answer what forest-scale question
it settles that comparison does not.
