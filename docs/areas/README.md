# The areas

**This is the index, not an area.** It exists so that an area nobody has written down yet says so
out loud, instead of being silently absent — because silence is what sends a session to the port
ledger or the old application to guess an answer.

**How to use it.** Find the area the work falls in and read that one file, whole. It is short by
design and it is the only file that needs reading before we talk. If the area is *not yet written*,
that is the honest state: **stop and ask**, and do not infer the answer from the predecessor, from a
ledger row, or from the shape of the code.

**Nothing on this page is authoritative.** Only a record in `docs/decisions/` with
`Status: Accepted`, and the code with its tests, state the product's position.

---

## Keeping it

| Area | File | State |
|---|---|---|
| How a run is stored | [how-a-run-is-stored.md](how-a-run-is-stored.md) | written |

## Making sense of it

| Area | File | State |
|---|---|---|
| Group Policy | [group-policy.md](group-policy.md) | written |
| Accepting a finding | [accepting-a-finding.md](accepting-a-finding.md) | written |

## Showing it

| Area | File | State |
|---|---|---|
| How results are shown | [how-results-are-shown.md](how-results-are-shown.md) | written |
| Reports and export | [reports-and-export.md](reports-and-export.md) | written |
| How the app looks | [how-the-app-looks.md](how-the-app-looks.md) | written |

---

## What keeps this page honest

`AreaFileGateTests` fails the build when this index and the directory disagree, in both directions:
an area listed as written that is not there, and an area file present that is not listed. It also
fails when a link out of one does not resolve, when a capability names a test that does not exist,
when two areas claim the same test as their evidence, and when an area file no longer governs a
single type some layer document has not already named — which is how a file the rewrite has
finished consuming says so instead of sitting on.

**The three-section check is gone.** It was deleted on 2026-08-21 under `P-51` because no change to
the product could make it fail, and because forcing three headings into a file being emptied meant
a page could not be shrunk toward nothing, only deleted whole.

**Nineteen areas were written on 2026-08-16; nine of those files have since been consumed and
deleted.** They were written all at once because the surface register is keyed to areas — every
public type had to be claimed by exactly one, so an area with no page left types with no home. That
is no longer how ownership works: a type is claimed by the layer document that describes it, and an
area file is an input the rewrite consumes rather than a fixture. An area the product has not
reached carries an honest empty *What is built* table and a *What has not been discussed* section
that says so plainly.

**A "not discussed" section written months before the work is still a guess**, and that has not
changed. Where a section is the agent's draft it says so; where the owner has deferred a question it
records the deferral and its reason. **Read a populated list as an argument, never as complete** — a
question that was never on the page is the one that gets inferred instead of asked.
