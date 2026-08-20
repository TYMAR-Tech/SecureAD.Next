# Design — challenges to the inherited shape

**Status: proposed, 2026-08-12. Nothing here is decided and nothing is built.**

> **Read against the code on 2026-08-13, and three of the five moved.**
> [`S-22`](S-22-what-the-old-app-does-with-the-data.md) read branches D, E and G — the analytical
> half — which is the evidence this document said it was waiting for. **Challenge 4 is confirmed and
> widened**, and is now the highest-ranked of the five. **Challenge 3 is confirmed and strengthened**,
> with one part of its framing refuted. **Challenge 5 is partly refuted**: the acceptance risk it
> names is already handled, and the residue is the inverse problem. **Challenge 1's premise does not
> survive** — it is marked *high confidence, arithmetic rather than taste*, and the arithmetic
> describes a shape the predecessor does not have; the reverse search it proposes is already
> implemented and the path table is capped rather than combinatorial. That is `F-S22-9`, and the
> challenge's text below is **left unrevised for the owner to correct or withdraw**. Challenge 2 is
> untouched and still decidable without further reading.

This document exists because the owner asked a question the rebuild had not asked itself: *setting
aside how the previous product did it, would you design this differently?*

That question is worth a document rather than a conversation, because the rebuild has been carrying
the predecessor's **shape** while carefully reviewing its **contents**. Every ledger row asks "port,
rebuild, delete or defer" — which are four answers to *what happens to this component*, and none of
them ask *should this component exist*. `0033` says nothing inherited is definitive; the map, the old
code and the old documentation are evidence rather than answers. The same scepticism has not yet been
applied to the architecture those components sit in.

**What is not in question.** The product is a point-in-time forest audit producing sealed evidence,
rules producing findings, and a control graph producing escalation paths. Several things about the
predecessor are simply right and are assumed throughout:

- every answer is read from a sealed bundle and never from a live directory, so a finding is
  reproducible a year later on a machine that has never seen the forest
- coverage is recorded positively and never inferred from absence
- chokepoint aggregation — *"fix this one entry and four thousand routes close"* — which is the most
  actionable output the product has
- evidence grading on paths, where `confidence`, `feasibility` and `validation_state` default to
  saying a path is graph reachability and **not** a validated exploitable route

Five things are challenged below. Two are strongly supported by measurement; three are opinion formed
from reading the schema rather than the code that writes it, and are stated as questions worth
answering rather than as conclusions.

---

## 1. Do not materialise the escalation path closure

**Confidence: high.** This one is arithmetic rather than taste.

`fact_escalation_path` stores discovered paths between principal pairs. A transitive closure over a
control graph grows combinatorially with the graph, not linearly — so the table's size is not a
tuning problem, it is the shape of the data. The predecessor's own benchmark note records *9M edges*
on paths the rebuild will reimplement.

**The observation that changes it: you never need all-pairs paths.** What the product actually
answers is *"which principals can reach Tier 0"*, and Tier 0 is dozens of objects, not millions.

So:

- store the **control edges**, which are bounded — S-20 measured ~11.3M entries across the distinct
  descriptors of a 100,000-object domain, and edges derive from those
- answer reachability by **reverse breadth-first search from each Tier 0 target**, which is bounded
  by principals × targets and runs against an in-memory edge set
- answer ad-hoc questions — *"what can this account reach?"* — by forward search on demand
- **materialise the answers that are displayed** (the Tier 0 reachability set, the chokepoint
  aggregation), never the space they were drawn from

The predecessor's `fact_escalation_chokepoint` already stores an *aggregate* rather than a space, and
that is the right instinct applied one level too late.

**What this costs:** an ad-hoc reachability question becomes a computation rather than a lookup, so it
must be fast enough to sit behind a screen. On an edge set that fits in memory that is a millisecond
problem, but it needs measuring rather than assuming, and `BenchmarkSuite1` is kept for exactly this.

**What it risks:** a question nobody anticipated becomes expensive, where a materialised closure
answers everything equally. That is the trade — and it is the right way round for a product whose
disk cost has already been the binding constraint once.

---

## 2. Split the file: sealed evidence, disposable analysis

**Confidence: high**, and it follows directly from a boundary already accepted in
[`S-20`](S-20-what-a-bundle-stores.md).

S-20 settled that the bundle has a captured layer and a derived layer, with the rule that every
derived table can be deleted and recomputed from the captured layer with no directory access. This
proposes making that boundary **physical**:

| File | Contents | Sealed | Rebuildable |
|---|---|---|---|
| `evidence.db` | the captured layer only — objects, attributes, descriptors, coverage | **yes** | no, ever |
| `analysis.db` | everything derived — parsed entries, closures, edges, reachability, findings | no | yes, from evidence alone |
| `annotations.db` | the customer's notes, acceptances and declared scope | no | no — it is customer input |

What it buys:

- **The seal covers observations and nothing else.** A seal over a mixture of fact and conclusion is
  hard to explain and weaker as evidence. A seal over "what the directory said" is neither.
- **Re-analysis becomes deleting a file.** [`0021`](../decisions/0021-re-analysis-produces-a-new-bundle.md)
  currently requires copying a bundle, analysing the copy and sealing it. With the split it is
  `File.Delete`, and the original evidence is untouched because nothing ever wrote to it.
- **The evidence can be archived or shipped without the bulk**, and the bulk is the part that grows.
- **A better algorithm next year applies to captures from this year**, with no ambiguity about which
  parts have been recomputed.

The predecessor asserted exactly this and did not do it. `DerivedStoreSchema.cs` opens with *"audit.db
is rebuildable, disposable, and never authoritative. Evidence is authoritative; SQLite is derived"* —
while `DirectObjectWriter` wrote LDAP results straight into that same SQLite file and no separate
evidence store ever existed (`F-S20-9`). The claim was true as a design intention and false as a
description, which is how the mixing went unnoticed for so long.

**Do this early or not at all.** It is nearly free while nothing writes derived data, and it is
invasive once five stages assume one connection to one file.

---

## 3. Make a finding's evidence structural rather than a blob

**Confidence: opinion.** Formed from the schema, not from the findings engine.

An audit tool gets challenged. *"Prove that `SVC-Build` can take over the CFO's account."* The answer
has to be produced quickly and has to be exact.

Today that lives in `fact_escalation_path.path_detail` (text) and `fact_finding.context_json`. Both
are strings assembled at derivation time, which means the evidence is a **rendering** rather than a
reference.

The proposal is that every finding references the **captured rows it rests on** — descriptor
identifier, entry ordinal, membership edge, object GUID. Three consequences:

- the interface can show a customer the actual bytes the directory returned, which is the difference
  between an audit tool and a scanner
- comparison can say *"this finding changed because **this** entry changed"* rather than reporting
  that two renderings differ
- a disputed finding is answerable by navigation rather than by re-running the analysis

This is close to free if the captured layer is keyed well, and the deduplicated descriptor design
from S-20 makes it cheaper still: an entry is identified by descriptor plus ordinal, and thousands of
objects share one descriptor.

---

## 4. The Tier 0 definition is a versioned input, and every finding records which one it used

**Confidence: opinion**, but the failure mode is specific and severe.

Everything in escalation analysis depends on what counts as Tier 0. It is customer-specific, it
changes over time, and getting it wrong produces either noise or false comfort — both of which
destroy trust in the whole output.

[`0006`](../decisions/0006-tier-0-and-expected-admin-are-separate-sets.md) already separates Tier 0
from expected administrators, which is the hard half. What is proposed here is narrower:

- the definition is an **explicit input**, not a derivation — a default from well-known relative
  identifiers, plus customer additions and exclusions, living in the annotations sidecar where
  customer input belongs
- it carries a **version**
- **every finding records the version it was computed against**

The reason is comparison. [`0023`](../decisions/0023-a-finding-has-a-stable-identity.md) works hard to
keep a finding's identity stable across rule changes so that acceptances survive. A change to the
Tier 0 set has exactly the same effect — every reachability result shifts — and nothing currently
records that it happened. Two runs compared across a tiering edit would report churn that looks like
change in the forest, which is the failure `0026` and `0027` exist to prevent, arriving through a door
neither of them watches.

---

## 5. Hygiene findings and reachability findings are different things

**Confidence: opinion**, though the strain is already visible in the records.

Two kinds of result are currently modelled as one:

| | Hygiene | Reachability |
|---|---|---|
| Subject | one object | a route between two |
| Origin | a rule over stored facts | emergent from the graph |
| Identity | stable — rule, subject, object | changes whenever anything on the route changes |
| Acceptance | *"this configuration is intended"* | *"this route is acceptable"* — a very different claim |
| Remediation | change one setting | break any link in a chain |

`0023` already notices this. It says rules whose subject is *a set* rather than a single object
"change identity when the set changes, and the finding returns", and then hands the problem to
comparison to sort out. That is a reasonable containment of the symptom; this proposes addressing the
cause by not forcing both shapes through one model.

The practical risk of leaving them merged is **acceptance semantics**. Accepting a hygiene finding
means "this setting is fine". Accepting a reachability finding means "this route is fine" — but the
route is made of links that exist for other reasons, and accepting it silently accepts every one of
them. That is a customer telling the product something they did not mean.

---

## What is deliberately not challenged

**Rules as data, logic as code.** [`0010`](../decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md)
is right and this document does not reopen it. One related note, offered without a proposal attached:
the predecessor's evaluators issue SQL directly — 15 queries against `fact_control_edge`, 18 against
`dim_delegation`, 3 against `fact_ace`
(`git grep -ho "FROM fact_[a-z_]*" -- src/SecureAD.Infrastructure/Findings/`). Every one of those is a
place storage and rules are coupled. Whether rules should instead express predicates over a small
stable vocabulary — *has control type over*, *is member of*, *is tier* — is worth asking when branch
E is designed, not here.

**The removal of live verification.** [`0008`](../decisions/0008-live-verification-is-removed.md)
stands.

**The rules themselves.** This is a document about shape. What the rules should look for is a product
question and a different exercise.

## What would settle these

1 and 2 are decidable now: 1 by measuring a reverse search against a real edge set, 2 by deciding
before anything writes derived data.

3, 4 and 5 are informed by the schema branch D and branch E write, **not by their code**, which does
not exist yet in the rebuild and was not read in the predecessor. They should be treated as questions
to carry into those sessions rather than as findings — and the review at
[`S-22`](S-22-what-the-old-app-does-with-the-data.md) is where the evidence for them should
come from. That session reads branches D, E and G — the analytical half — because branches A, B and C
were read on 2026-08-12 and `S-20` records exactly what that reading did and did not cover.
Challenge 1 is squarely in its scope; challenge 2 is decidable without it.
