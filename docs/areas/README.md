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

## Getting the data

| Area | File | State |
|---|---|---|
| Which controller we read, and whether we can | [which-controller-we-read.md](which-controller-we-read.md) | written |
| Domains we deliberately skip | [domains-we-skip.md](domains-we-skip.md) | written |

## Keeping it

| Area | File | State |
|---|---|---|
| How a run is stored | [how-a-run-is-stored.md](how-a-run-is-stored.md) | written |
| How the run library stores and lists runs | [the-run-library.md](the-run-library.md) | written |

## Making sense of it

| Area | File | State |
|---|---|---|
| How privilege escalates | [how-privilege-escalates.md](how-privilege-escalates.md) | written |
| Group Policy | [group-policy.md](group-policy.md) | written |
| What we call a finding | [what-we-call-a-finding.md](what-we-call-a-finding.md) | written |
| Accepting a finding | [accepting-a-finding.md](accepting-a-finding.md) | written |

## Showing it

| Area | File | State |
|---|---|---|
| What goes into the new audit wizard | [the-new-audit-wizard.md](the-new-audit-wizard.md) | written |
| How results are shown | [how-results-are-shown.md](how-results-are-shown.md) | written |
| Reports and export | [reports-and-export.md](reports-and-export.md) | written |
| How the app looks | [how-the-app-looks.md](how-the-app-looks.md) | written |

---

## What keeps this page honest

`AreaFileGateTests` fails the build when this index and the directory disagree, in both directions:
an area listed as written that is not there, and an area file present that is not listed. It also
fails when an area file is missing one of its three sections, when a link out of one does not
resolve, when a capability names a test that does not exist, and when two areas claim the same test
as their evidence.

**Every area now has a file, and that is not the same as every area being discussed.** All nineteen
were written on 2026-08-16 because the surface register is keyed to areas — every public type must be
claimed by exactly one, so an area with no page leaves types with no home. An area the product has
not reached carries an honest empty *What is built* table and a *What has not been discussed* section
that says so plainly.

**A "not discussed" section written months before the work is still a guess**, and that has not
changed. Where a section is the agent's draft it says so; where the owner has deferred a question it
records the deferral and its reason. **Read a populated list as an argument, never as complete** — a
question that was never on the page is the one that gets inferred instead of asked.
