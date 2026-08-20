# 0015 - A delegation bundle names a pattern; it never explains one away

Date: 2026-08-10
Status: Accepted. *Signed bundle* was corrected to *sealed* below, per
[0030](0030-the-product-produces-sealed-evidence-never-signed.md); where an annotation lives is
unchanged.

## Context

Delegation bundle matching recognises a set of ACEs as a pattern an administrator would know -
"Reset user passwords", "Join a computer to the domain" - and records the match. Sixteen bundles
exist: eleven mirroring the Delegation of Control wizard's tasks, five naming attack primitives such
as write-DACL and shadow credentials.

Nothing in the findings layer reads those matches. A bundle currently adds a name and changes no
verdict, and that is the property everything below depends on.

Sixteen patterns will not describe a real forest. Organisations repeat their own delegations across
dozens of containers, and those combinations match nothing, so an auditor sees a raw mask and a
GUID repeated forty times with no indication that it is one intentional pattern. The obvious answer
- let customers define their own bundles - was considered and rejected. Defining an ACE pattern
requires stating masks, scope GUIDs, inheritance and required-versus-optional membership, which is
the Advanced Security Settings dialog with a set-builder on top, and its failure mode is silence: a
pattern that does not match says nothing about why.

[`0010`](0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md) already excludes customer-supplied
rules, on the grounds that anything the product reports is something the product can be held to. A
bundle definition is an interpretation rule in different clothing.

## Decision

A bundle names a pattern. It never suppresses, downgrades, or excuses a finding. A permission that
is dangerous inside a recognised delegation is exactly as dangerous as it was outside one.

Bundle definitions ship with the product. There is no editor and no customer-supplied definition
file.

What a customer may do is name what the product found. Objects are grouped by their canonical ACE
set, repeated sets are surfaced, and a customer may attach a name to one. That name is an
annotation about their organisation, so it lives in the sidecar beside notes and tier overrides,
never in the sealed bundle, and it is rendered as the customer's word rather than the product's.

Grouping is by exact canonical ACE set. A container carrying one extra permission forms its own
group and is reported as a variant rather than absorbed into the pattern it nearly matches.

## Consequences

The one place a customer could have hidden a dangerous permission behind a friendly label is closed
before it opens.

Exact grouping surfaces the case a tolerant matcher would bury: a delegation applied consistently
to thirty-nine containers and differently to one. That divergence is usually the interesting one.

Storage must record a canonical ACE-set hash per object. It is cheap while the schema is being
designed and expensive to add afterwards, and without it only the rejected approach remains
available.

Matching runs during analysis over stored ACEs, so a pattern added in a later build applies to
captures already taken. A customer with an unrecognised delegation gets it named in the product and
re-analyses existing evidence, rather than being handed a configuration file.

What the product reports about an ACE matching no pattern is not settled here. It is the same
question as an unnameable GUID and deserves one answer.
