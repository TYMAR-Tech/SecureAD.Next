# Slice template

Copy to `docs/review/NN-name.md`. Keep the sections and their order — identical structure
across slices is what makes gaps visible. A slice with an empty "verified-safe" section
probably was not looked at hard enough.

---

# NN — <subsystem>

**Type:** slice | sweep
**Reviewed at commit:** `<sha>`
**Size:** <n> files, <n> lines
**Date:** YYYY-MM-DD

## What it does

Two or three sentences in product terms, not implementation terms. What would a customer
lose if this subsystem vanished?

## Shape

Entry points, the main types, and what owns what. A short list, not a class diagram.

## Dependencies

- **Depends on:** …
- **Depended on by:** …
- **Layering violations:** any reference that crosses a boundary the wrong way, or a type that
  is `internal` where a legitimate consumer sits in another assembly.

## Verified-safe

Things checked and found correct. Recorded so they are not re-investigated.

- **<claim>** — evidence at `file:line`.

## Findings

One block each. Delete the severity levels that do not apply.

### F-NN-1 — <short title>

- **Severity:** breaks-for-user | correctness-risk | maintainability | cosmetic
- **Confidence:** verified | suspected | needs-environment
- **Evidence:** `file:line` (and a second site if it is duplication)
- **What happens to a user:** plain language. If this cannot be answered, drop the finding.
- **Why it is this way:** history or constraint, if known. Often there is a good reason.
- **Options:** what could be done, with the trade-off of each.
- **Test cover:** which tests exercise this today. If none, say so — that changes the risk of
  any fix.
- **Status:** OPEN | PARTLY REPAIRED | REPAIRED | DEAD | RETRACTED | REFUTED, with the date it was
  last checked against the code. **Required**, and last so it is the line a reader lands on.

**Every finding must declare a status, and `FindingRecordTests` fails the build if one does not.**
This field was missing from the template until 2026-08-07, which is why six findings in one slice
had no status at all: the thing most likely to go stale was the one thing there was no field for.

A status is a claim about *the record*, not only about the code. `OPEN` on an entry nobody has
re-read since filing is a different statement from `OPEN` verified today, so say which. A repair
that closes a finding updates this field **and** the open list in `README.md` — a finding whose fix
has shipped is a lie about the state of the product, and `FindingRecordTests` also fails when a
finding exists in a slice file but not in that list.

Prefer splitting a status over averaging one. `PARTLY REPAIRED` must name which half is done and
which is live, or it is indistinguishable from `OPEN` to the next session.

**Do not type a count into a finding. Write the command that produces it**, next to the number:

```
~73 swallowed sites (`git grep -c "catch (SqliteException)" -- src`, measured at <sha>)
```

A number typed once is a number nobody can re-check. F-01-30 said "~35 sites" when there were 73 —
a 2x planning error that survived because there was no way to reproduce it.

## Open questions for the owner

Decisions needing product judgment rather than a technical answer.

## Not reviewed

What was deliberately skipped in this slice and why — so the gap is known rather than assumed
covered.
