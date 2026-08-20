# Design — measuring and comparing risk

**Status: nothing here is built, and no test binds it.** This is a design note recording decisions
taken in review on 2026-08-12, so that the work that eventually builds it starts from the reasoning
rather than from memory. It is deliberately not named `S-*`, because the `S-` documents describe
things that exist.

> **Corrected 2026-08-13 in `S-26`, as `F-S26-5`.** That status is no longer true of all three
> pieces. The **summary** and the **comparison** were built on 2026-08-12 in
> [`S-18`](../next/S-18-run-identity-and-comparability.md) - `RunSummary`, `RunCoverage`,
> `ComparabilityOutcome` and `RunComparability` live in `SecureAD.Evidence`, ledger rows `F1`,
> `F2`, `F3`, `F9` and `F10` read `Done`, and `RunComparabilityDocumentationTests` binds them. What
> remains unbuilt is the **baseline**, and the doors that call the verdict: `F17` reads *rule built,
> no door calls it*.
>
> The header is corrected rather than the body, because the reasoning below is what the built code
> was built from and still explains it. Read it as the design that was carried out in part, not as a
> proposal.

Three related pieces: a **summary** each run records about itself, a **comparison** between two runs,
and the **baseline** that says which run to compare against.

## What this is for

An administrator does work — closes delegations, removes stale privilege, breaks escalation paths —
and then has to show somebody that the environment is safer than it was. That is the use this is
designed for, and it sets the bar: the output has to survive being shown to a person who is not sure
they believe it.

Which produces the one rule everything else follows from.

## The rule: improvement by fixing must be distinguishable from improvement by excusing

Findings can be accepted in the sidecar. So a fall in the number of findings means either *we fixed
things* or *we excused things*, and a summary that cannot tell them apart is a tool for manufacturing
improvement. That is what [`0015`](../decisions/0015-a-bundle-names-a-pattern-it-never-explains-one-away.md)
forbids, arrived at from the reporting side.

**Every count is therefore three numbers: found, accepted, remaining.** A fall in *remaining* that is
not matched by a rise in *accepted* is real work, and the person being shown it can see that for
themselves.

## The summary

**It lives inside the bundle and under the seal.** Outside the seal it is not proof, it is a
spreadsheet.

**It is stored as name and value rows, not as fixed columns.** This is the opposite of the choice
made for objects in [`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md), and the
reason for the difference is worth stating: this is dozens of rows rather than millions, the set is
expected to change as the product learns what matters, and nothing queries it at scale. Adding a
metric is then data, not a schema change.

**Each metric carries the version of its definition.** Redefining a metric while keeping its name is
the one change that produces a lie — a chart drawn across the boundary compares two different things
and says they are the same measurement. So a definition is never revised in place: the old name is
retired and a new one added, and a chart that spans a change refuses to draw rather than drawing
something misleading.

### What to count

Object counts are not risk. The candidates, each as found / accepted / remaining where the idea
applies:

| Metric | Why |
|---|---|
| Findings by severity | The work list, and the headline |
| **Principals that can reach Tier 0** | Probably the single most meaningful number the product produces |
| Distinct escalation paths to Tier 0 | Breaking one path matters even when the count of principals does not move |
| Shortest path length to Tier 0 | Longer is better; it measures depth of defence rather than count |
| Unconstrained delegation hosts | A small, countable, fixable population |
| Accounts carrying `adminCount` that are no longer privileged | Residue of past privilege, and cheap to clear |
| Domains attempted versus succeeded | Not a risk metric — the guard on all the others |

That last row is what stops a number that fell because a domain went unread from reading as progress.

### Why not a separate trend file

A file outside the bundles, accumulating metrics over time, was considered and rejected. It would be
a second copy of facts that already exist, unsealed, with no lifecycle and no owner, and — the
deciding argument — its numbers are not comparable unless coverage is, so it would eventually draw a
line comparing a nine-domain run with an eight-domain one.

The real need behind it survives: bundles are large, people will delete old ones, and history should
not die with them. That is answered by **keeping a deleted run's summary as a tombstone** — which is
explicitly a record of something that no longer exists, rather than a shadow copy competing with a
live source.

## The comparison

**Compare the conclusions, not the evidence.** In a large forest thousands of objects change between
two runs and nobody will read that twice. Permissions barely move — a delegation is set once and sits
for years — so a comparison scoped to *who can take over what* is a handful of rows and is worth
reading.

Four layers, coarsest first:

1. **The headline** — the summary numbers side by side. *"Paths to Tier 0: 47 → 12."*
2. **Findings** — new, gone, still present.
3. **Escalation paths to Tier 0** — opened and closed.
4. **Permissions** — only on Tier 0 objects and objects carrying findings. Never the whole forest.

**A finding that has gone has three explanations and they are never collapsed:** genuinely resolved,
the object was deleted, or this run could not read where it lived. The third rendered as the first
tells a customer their problem is fixed when it is merely invisible. Findings carry their own
coverage, so this is answerable rather than guessed.

Comparison also carries the work described in [`0023`](../decisions/0023-a-finding-has-a-stable-identity.md):
where a rule's subject is a *set*, a changed set changes the finding's identity, and comparison
recognises the overlap and reports it as **changed** rather than as one thing resolved and another
appearing.

## The baseline

Two different questions, and the previous design had one answer for both:

- **"What changed since the last run?"** — operational, frequent. Needs no marker at all; it is the
  previous run by date, and it comes free.
- **"What changed since we signed off?"** — the baseline. A human act.

**A baseline is never set automatically.** It is an assertion that somebody looked, and advancing it
on a schedule manufactures that assertion — findings nobody reviewed would silently become the
accepted state. The prompt belongs on closing the application rather than at the end of a capture,
because signing off should follow review, and at the end of a capture nobody has looked at anything
yet. It should not appear when there is nothing new to sign off on.

With one forest there is one profile, so the elaborate profile grouping of the previous design
collapses into a single nominated reference run.

## Open

- The metric set above is a starting position, not a settled list. It is cheap to tune because
  metrics are rows, and because [`0021`](../decisions/0021-re-analysis-produces-a-new-bundle.md)
  allows an added metric to be computed retrospectively from sealed captures.
- Where the tombstone record lives depends on the run library model, which is undecided.
