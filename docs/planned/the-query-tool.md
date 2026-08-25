# Planned: the query tool

**Status: not built. Wanted by the owner for customers, ruled 2026-08-25, and explicitly not
urgent.**

The predecessor carried a query tool that ran reports against the captured database and let a
customer write their own. It is wanted again. This document exists so the feature survives outside a
conversation, not because it is scheduled.

---

## What it is for

The owner's position, stated 2026-08-25, is that SecureAD is **not** a policy compliance checker -
plenty of software measures password strength and settings posture. What he wants instead is that
the information be **visible on the object** and **queryable**, so a customer who wants a list of,
say, last password-change times across the forest can ask for one, export it and read it.

That is a different product shape from a rule. A rule states a position the product will defend. A
query answers a question the customer asked. The query tool is how the product says *here is what we
captured* without claiming *and here is what we think of it*.

## Why it is cheaper than it looks

A bundle is a SQLite database. The data is queryable the moment capture seals it, by any SQLite
client, with no work from this product at all. What has to be built is the surface - somewhere to
type a query, somewhere to read the answer, and a way to get it out - not an engine.

## Three constraints it must meet

**Read-only against the evidence.** The evidence file is sealed and a query must never open it for
writing. A query tool that could modify evidence would break the seal that
[`0085`](../decisions/0085-judgement-writes-beside-the-evidence.md) exists to protect, and the
customer would have destroyed his own proof by looking at it.

**Honest about coverage.** This is the one that needs design rather than plumbing. A customer
querying `pwdLastSet` across a forest where one domain was not read gets a confident-looking table
that is quietly missing a domain. A result set must be able to say what it could not see, in the
same way a finding does - which is
[`0086`](../decisions/0086-a-qualified-statement-beats-silence.md) applied to a surface that has no
rule behind it.

**It states what it is.** Query output is captured evidence, not a judgement. Nothing it returns
carries a severity, and the product does not stand behind an interpretation the customer drew from
it.

## What is not decided

- Whether the customer writes SQL, or picks from a set of prepared queries, or both. The predecessor
  offered both - 29 prepared reports plus a builder.
- Whether saved queries live with the run, with the installation, or nowhere.
- What export formats are supported. The predecessor had CSV and HTML.
- Where it sits in the shell.

## When

After findings exist. A query tool over a bundle that has no findings in it answers half the
questions a customer would ask of it, and the coverage-honesty design is easier to settle once
there is a finding surface doing the same job to copy from.
