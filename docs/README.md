# SecureAD documentation

Nothing here is published. The repository is private and these are read as markdown, on GitHub or
in the editor.

## The tree

```
docs/
  README.md                    this index
  ARCHITECTURE.md          â”
  CAPTURE-PIPELINE.md      â”‚
  CONFIGURATION.md         â”‚
  CONTROL-EDGES-AND-PATHS.mdâ”‚  reference â€” how the shipped system works
  DATA-MODEL.md            â”‚
  GROUP-POLICY-CAPTURE.md  â”‚
  INVARIANTS.md            â”˜
  decisions/                   why the product is the way it is â€” the only settled record
  rules/                       one card per SEC-* findings rule
  work/                        active queues â€” backlogs, design logs, audits
  review/                      the architecture review record
  map/                         what the shipped system contains, branch by branch
  next/                        the rebuild: its architecture, registers, ledger and slices
```

**Two products live in this tree, and the top level describes the shipped one.** `next/` holds
the rebuild â€” a separate solution under `next/`, with its own architecture, its own registers and
its own slice documents. A fact about the rebuild is never in the top level, and a fact about the
shipped product is never in `next/`. `map/` sits between them: it is the inventory of the shipped
system that the rebuild is being derived from.

**Nothing outside `decisions/` is settled.** A decision record with `Status: Accepted`, and a
finding carrying an explicit **Decision:**, are the only statements in this tree that may be
treated as the product's position. Everything else â€” every slice document, every review, every
design note, every finding without a decision â€” is discussion, interpretation, or a record of what
somebody understood at the time. Read it as argument, not as instruction. This applies to
well-written documents most of all, because those are the ones that read like conclusions.

**The top level is reference only.** If a file sits directly in `docs/`, it describes how the
system works now and is expected to be true. Everything else is in a subfolder that says what it
is.

**A folder exists here for exactly one of two reasons**, and if it has neither it should be
flattened:

- **Volume** â€” a set of many same-shaped files that would drown the handful you actually read.
  `rules/` holds 67 cards; `decisions/` is a numbered series that only grows.
- **Kind** â€” event documents, which record what happened during an activity rather than how the
  system is. `work/` and `review/` hold these, and keeping them out of the top level is what makes
  the positional rule above mean anything.

A folder holding one file is not organisation, it is a hiding place.

## Reference

Maintained descriptions of the product. If a change makes one of these wrong, fix it in the same
change.

| Document | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Projects, layering, the three-axis run model, data flow, service lifetimes, logging, threading |
| [DATA-MODEL.md](DATA-MODEL.md) | Every table, view and metadata key, what an absent one means, the sidecar |
| [CAPTURE-PIPELINE.md](CAPTURE-PIPELINE.md) | Phases, failure handling, the three-axis run model, degraded runs |
| [CONTROL-EDGES-AND-PATHS.md](CONTROL-EDGES-AND-PATHS.md) | How control edges and escalation paths are derived |
| [GROUP-POLICY-CAPTURE.md](GROUP-POLICY-CAPTURE.md) | Group Policy and SYSVOL capture, and the findings it drives |
| [CONFIGURATION.md](CONFIGURATION.md) | Settings, capture profiles, connection options |
| [INVARIANTS.md](INVARIANTS.md) | Properties that must never break, and the tests enforcing them |
| [rules/](rules/README.md) | One card per `SEC-*` rule, plus the first-party claim verification ledger |

Two of these are known to be thin: `ARCHITECTURE.md` names 44 of the product's 746 types, and
`CONFIGURATION.md` documents 2 of 43 settings. Both are queued for rebuild â€” see
`work/DOCUMENTATION-AUDIT.md`, which stayed in the predecessor repository. **Both carry a banner saying so.** A
document sitting in the top level is claiming to be true, and one covering 5% of its subject is
claiming more than it can support until the banner is there to correct it.

The [root README](../README.md) is the front door: what the product is, how to build and run it.

## The rebuild

[next/](next/README.md) is a second product in the same repository: its own solution under
`next/`, its own architecture, its own tests. Nothing in the top level describes it.

**Start here, in this order, before changing anything in `next/`:**

| Document | What it is | Kind |
|---|---|---|
| [next/READING-ORDER.md](next/README.md) | The path one object takes through the code, file by file, with what each answers. **Start here to understand how it works** | state |
| [next/README.md](next/README.md) | How the rebuild works: gates, how a session runs, what counts as documentation | state |
| [next/WHAT-THE-OLD-APP-HAD.md](next/WHAT-THE-OLD-APP-HAD.md) | Every row of work â€” `A2`, `B6`, `C1` and the rest â€” with its status. **The row numbers cited everywhere else are defined here** | state |
| [next/ARCHITECTURE.md](next/ARCHITECTURE.md) | The three projects and the layering rule, enforced by `ArchitectureDocumentationTests`. Distinct from the top-level `ARCHITECTURE.md`, which describes the shipped product | state |
| [next/CONCEPT-REGISTRY.md](next/CONCEPT-REGISTRY.md) | One name per concept, so two components cannot invent two words for one thing | state |
| [next/SURFACE-REGISTER.md](next/SURFACE-REGISTER.md) | Every public type in the rebuild and the row that justifies it | state |
| `next/S-*.md` | One document per slice. **Mixed kind â€” see below** | mixed |
| [next/sessions/](next/sessions/README.md) | The prompt that produced each slice | event |

**The `S-*` documents are the one place this tree's own rule is not held.** Some describe how a
component is â€” `S-16` is the bundle, and a test binds it to the schema. Others are the record of
what one session found â€” `S-24` is findings, retractions and open questions. They share a folder
and a naming convention, so a reader cannot tell which they are holding without opening it. Per
*Two kinds of document* below, that is the mixing that makes a pile grow. Splitting them is owed
and is not yet done.

## The shipped system, branch by branch

[map/](map/README.md) inventories the shipped product one branch at a time â€” `A-connect-and-discover`
through `K-cross-cutting`. It is what the rebuild is derived from: a slice document reasoning about
capture is reasoning against `map/B-capture.md`.

It is **state, and dated by nature** â€” it describes a system that is not being changed. Treat a
disagreement between `map/` and `src/` as `map/` being stale, never as a finding about the code.

## Decisions

[decisions/](decisions/README.md) holds short dated records of choices a later reader could
reasonably second-guess â€” why there is no backward compatibility, why a missing view is reported
as a degraded run. A record wholly replaced is superseded; a record partly overtaken is corrected in
place, keeping its Context section as written. See [0032](decisions/0032-a-decision-record-is-corrected-in-place.md).

## Work queues

The working documents - `work/PUNCH-LIST.md`, `work/PRODUCT-REVIEW.md`,
`work/DOCUMENTATION-AUDIT.md`, `work/RUN-MODEL-DESIGN.md` and the `review/` architecture review -
stayed in the predecessor repository when the rebuild was cut loose. They routed work on the old
application and were never the source of truth about how this system behaves.

Two files came across because session prompts cite them by name: `review/TEMPLATE.md` and
`review/SESSION-LOG.md`. They are here so the record of what each session was told stays
readable, not because they describe the product.

## Two kinds of document

This is why the tree has the shape it does.

A **state** document describes how the system *is*. It can be edited forever and every edit makes
it more accurate. Reference, rules and invariants are this kind.

An **event** document records what happened during an activity. It can only accumulate, because
updating a record of what was observed in May falsifies it. Findings, design logs and audits are
this kind.

Mixing them is what went wrong before. When durable conclusions get written into event documents,
the only way to add anything is another event document â€” so the pile grows, the reference
documents stand still, and each effort rediscovers what the last one concluded.

## One home per fact

For any fact about the product you must be able to name its single home without hesitating.

| Question | Home |
|---|---|
| What does `derived_health` mean? | `DATA-MODEL.md` |
| What happens when a phase throws? | `CAPTURE-PIPELINE.md` |
| May a reader assume a view exists? | `INVARIANTS.md` |
| Why is there no backward compatibility? | `decisions/` |
| What does SEC-063 detect? | `rules/SEC-063.md` |

Two plausible homes means the documents overlap and one is describing what it does not own. No
home means a reference document is missing. *"It is in a finding"* means it is not documented â€”
findings route the next session and are invisible to everyone else.

This is rule 8 in `review/README.md`, which stayed in the predecessor repository.

## Conventions

- Reference documents are written in the **present tense**, from the code. No `F-` numbers, no
  account of the repair that produced the fact, no "as of this session".
- **Verify against the definition, not against adjacent prose.** Two errors in this documentation
  came from trusting an XML doc comment and a document's own dated appendix instead of opening the
  enum and the writers.
- A document that must stay dated says so at the top and does not live in the top level.
- Retire a document with `git mv`, then update this index. **Grep the whole repository for the old
  path, not just `docs/`** â€” `src/`, `tests/`, `.github/` and `.gitattributes` all reference
  documents.
- Do not hardcode volatile counts where avoidable â€” prefer "60+".
