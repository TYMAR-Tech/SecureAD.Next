# Session prompts

The instruction set each session was given, one file per session.

## Why these are files

A session prompt is the closest thing this project has to a specification: it names what is in
scope, which documents govern it, which rules bind it, and what finishing looks like. Until
2026-08-12 it was assembled by hand into a chat window each time, from a template in
[`../README.md`](../README.md). That had three costs.

**The prompt actually used was never recorded.** The template survived; the expansion did not. So
*what was this session told to do* had no answer, and a slice document could not be checked against
its own brief.

**Each expansion was a fresh chance to drop a rule.** The template names the rules by section rather
than repeating them, which is deliberate — a prompt carrying copies of the rules drifts from them
and nothing can reconcile the two. But an expansion that quietly omits *§Tests* is indistinguishable
from one that includes it, unless somebody remembers.

**Nothing checked that a prompt pointed at documents that exist.** A session sent to a renamed file
finds nothing and carries on.

The old codebase already solved this once, in `SessionPromptTests`, which asserts that every section
and every document its review prompt names exists. **That test governs the old tree only** — it reads
`docs/review/README.md`'s `## Session prompt` section and nothing under this folder. The rebuild once
carried its own `SessionPromptTests`; it was deleted deliberately on 2026-08-14, for the reason
[`../README.md`](../README.md) records: it could not be broken by any change to the product, and what
it could not check was the part that mattered — whether the scope is the right scope. **No prompt in
this folder is machine-checked.** The shape below is held by a reader, not by a build.

## How a session starts

Write the prompt into a file here first, named for the slice it will produce — `S-19-…` for the
session that writes `S-19-…`. Then start the session by pointing at that file. The prompt is
reviewed before the work rather than after it, and it is in the repository either way.

**A handoff is two lines, not a prompt.** The prompt is the file; repeating it into a chat window
is what this folder exists to stop. When one session hands over to the next, it names the file and
says what state the tree is in. Nothing else.

## Prompts that have not been run

A prompt is named for the slice it will produce, so a prompt with no slice document means the
session has not happened. That is a legitimate state — a prompt is written and reviewed before the
work — but it is only legitimate while it is **visible**. An unrun prompt that nobody has recorded
is indistinguishable from a session that ran and never wrote its document, and the second is a
session whose findings are gone.

| Prompt | Produces | State |
|---|---|---|
| [`S-27-the-capture-to-bundle-seam.md`](S-27-the-capture-to-bundle-seam.md) | `S-27-…` | **Not run.** Written 2026-08-13, after `S-21` closed. The next building session |
| [`S-46-the-exclusion-attestation.md`](S-46-the-exclusion-attestation.md) | `S-46-…` | **Not run.** Written 2026-08-16. Deferred at the owner's direction so the wizard's behaviour on opening could be settled first |
| [`S-47-a-window-that-discovers-on-its-own.md`](S-47-a-window-that-discovers-on-its-own.md) | `S-47-…` | **Part run.** Written 2026-08-16. Three steps committed, none of them behavioural: the disjointness tests, the widened access gate, and the `Preflight.cs` split |
| [`S-51-what-an-object-is-beyond-its-permissions.md`](S-51-what-an-object-is-beyond-its-permissions.md) | `S-51-…` | **Closed.** Attribute values are readable out of a bundle, catalogue version 3, and every section of the object view shows something. `userAccountControl`, timestamps, `groupType` and `gPLink` worded against Learn; `whenChanged` refused for not being replicated |

**`S-27` is written and waiting**, which is the state this table exists to make visible. It builds
the entry point that runs a capture into a bundle — ledger row `C15` — and settles what `B9` and
`B10` still owe, since `BundleWriter` appears to have been built out from under them by `C1`.

**It is the first session with no oracle**, and the prompt says so under its own heading. `S-21`
could read the parser against `[MS-DTYP]`; `GoldenAceHashTests` could prove the port changed
nothing. Nothing says what a correct bundle looks like for a given capture, so the tests will be
invented — and an invented test agrees with the code by construction.

**`S-21` was the entry here before it, and it is gone because the session ran.** It was written
2026-08-12 alongside `S-20`, sat unstarted and unrecorded for three days, was recorded here on
2026-08-13 by `S-26` as `F-S26-6`, and ran the same day producing
[`S-21-the-security-descriptor-parser.md`](../../history/S-21-the-security-descriptor-parser.md). An entry is
removed rather than marked done. An earlier draft of this file said `SessionCompletionTests` held
this table in both directions; **no such test has ever existed** (`F-S39-1`). The convention is kept
by hand: an entry is removed when its session runs, and the slice document it produced is the record
that it did.

**Why it mattered that `S-21` was invisible.** It reviews the security descriptor parser against
Microsoft's published specification rather than against the tests. Row `K15` read `Done` and was
bound by `SecurityDocumentationTests`, so nothing in the ledger or the suite suggested anything was
owed. But `GoldenAceHashTests` and the canonicalisation fixtures were, per §`Tests`, *"computed once
and hardcoded"* from the predecessor and copied across byte for byte: they prove **fidelity to the
predecessor**, not **correctness**, so a misreading inherited from the old parser passes every test
in the tree. A row reading `Done` and bound was the condition under which the review was most needed
and least likely to be remembered — and the session found six discrepancies, two of which can change
a permission the product reports.

## What a prompt must contain

Held by a reader rather than by a build — see above, and `F-S39-1`:

- **`## Scope`** — what this session covers, and what it deliberately does not.
- **`## Read first`** — the documents that govern it. Every path named must exist. Every section
  named must be a real heading in [`../README.md`](../README.md). A section reference is written
  ``§`Exact heading text` `` — the backticks are the delimiter, because guessing where a heading
  name ends in flowing prose does not work, and an exact delimiter also stops the check being
  satisfied by a heading that merely starts the same way.
- **`## Rules`** — the constraints. Named by reference, not copied.
- **`## Finish by`** — what done looks like.

What the test cannot check is whether the scope is the right scope, or whether the rules chosen are
the ones that matter. That is a reader's job, and it is why the prompt is written down before the
session rather than reconstructed after it.
