# 0011 - The rebuild's documentation is written fresh and bound by tests

Date: 2026-08-09
Status: Accepted

## Context

The existing documentation is roughly thirty-three thousand lines, written across a period in which
the product's identity changed more than once. Much of it is excellent and some of it is no longer
true, and the two are not distinguishable by looking. The map found six classes of claim that were
accurate when written and are not now, each found independently by sessions that could not see one
another's work.

Moving those files alongside the code would carry the untrue ones across without anyone deciding to,
because a document that changes folder is not thereby reviewed. The alternative usually proposed —
a documentation pass at the end — is the one that historically does not happen, or happens after the
reasoning has been forgotten.

The repository already contains the mechanism for the harder half of this. `DataModelDocSyncTests`
compares `DATA-MODEL.md` to the schema the code creates and fails the build on a mismatch, and two
sibling tests do the same for the capture phases and the run model. Where that binding exists, a
document cannot drift silently.

## Decision

The new implementation's documentation is written fresh, in its own library, and no document is
carried over.

Existing documents are source material: read for what they establish about the product, and not
promoted by being moved. A specification that proves correct is rewritten unchanged in substance,
and it is still a specification that was checked.

**A document is not the new implementation's documentation until a test binds it to the new code.**
Binding is what makes "this was reviewed" verifiable by someone who has not read it, rather than an
assurance.

Documentation is part of a component's work, not a phase after it. A component whose code is built
and whose documentation is not written and bound is unfinished.

Decision records are the exception. They are dated, and they are reviewed for whether they still
bind: a record wholly replaced is superseded, and a record partly overtaken is corrected in place
per [0032](0032-a-decision-record-is-corrected-in-place.md), which keeps its Context as written.

## Consequences

Each component costs more, and the estimate is roughly a fifth to a third again. That is the price
of the guarantee and it is accepted deliberately.

Binding cannot assert that an explanation is any good — only that it names what exists and omits
what does not. Human review is still required and is not replaced by a green test.

Documentation that no test can bind is allowed, and must say so, so that the absence of a test is
never read as the absence of a claim.

The old library is deleted with the code it describes rather than maintained in parallel, so there
is never a period in which two documents describe the same subject and disagree.
