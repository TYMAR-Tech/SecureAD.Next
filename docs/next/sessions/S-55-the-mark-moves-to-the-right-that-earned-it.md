# S-55 — The mark moves to the right that earned it

**Status: closed. See *What this session leaves behind*.**

Written 2026-08-18, continuing from [`S-54`](S-54-a-property-set-is-what-it-contains.md). Read its
*What this session leaves behind* first, then
[`0076`](../../decisions/0076-the-mark-attaches-to-the-right-that-earned-it.md) and the
[`0074`](../../decisions/0074-red-marks-a-takeover-permission-when-the-operator-asks.md) it amends.

**The tree was at `build Z`, 1,653 tests green, committed at `508bf98e`.** `S-54` settled Option C
in principle and left it unbuilt. This built it.

---

## Why this

`S-54` closed with Option C agreed and not done, and with its grounds already established: an
`ACCESS_MASK` is a set of bits Windows evaluates independently, `AccessCheck` tests each right and
accumulates across entries, and `DangerousPermissionClassifier` judges them differently by
construction. A row showing several rights under one *Takeover* mark states something true of the
entry and useless about the rights — the administrator deciding what to remove cannot tell which
half earned it.

**This was not re-derived from data, and that is deliberate.** A measurement of how often marked
rows carry mixed verdicts was run in `S-54` and deleted, because the owner asked why the product was
being measured for something Learn had already settled. The finding is structural, not statistical.
It does not become more or less true at 5% or 60%.

---

## What was built

`PermissionWording.Rights` stopped being a list of strings. Each right now carries the mask bits
that produced its words and whether this build has a word for them at all. Per-right classification
then needed **no new judgement**: it is the existing classifier asked about one right's bits at a
time, and its arms already tested single bits. Not one verdict about any right changed.

In the shell, `PermissionRightViewModel` holds one right, its own assessment, its own mark and its
own reason, with the operator's toggle pushed down to it. The `Risk` column is gone and each right
is rendered on its own line with its mark beside it.

**The entry keeps a verdict that nothing renders.** It is the loudest thing said about any one of
its rights, *derived* from them and never asked of the classifier a second time. Two independent
answers about one entry is the six-places-disagreeing defect this component exists to end. The
counters count entries, an entry with any dangerous right counts once, and what the strip means to
an operator is unchanged.

**1,669 tests, at `build AA`.**

---

## The three things worth carrying forward

### `F-S54-2` arrived on schedule, in a place nobody was watching

The classifier expanded generic rights out of the whole mask itself. That meant an unexpanded
`GENERIC_ALL` reaching the screen was judged a takeover **whatever the wording made of it** — the
classifier was quietly covering for the wording.

Option C inverts that dependency: the wording now chooses which bits the classifier is asked about,
and `GENERIC_ALL` is a bit the wording has no word for. So the most open entry in a forest would
have become one unclassifiable right, and the row would have said nothing about full control.

`PermissionEntry` documents its mask as already expanded, so in practice nothing was broken. **That
is exactly why it was worth closing anyway.** The defect would have arrived through a contract this
code cannot check, in the one direction that matters, and the count would have moved the reassuring
way while it happened. The permission list expands before wording and does not rely on the promise.

### An unnamed bit must be refused, not asked about

The left-over item — `other rights (0x…)` — cannot be handed to the classifier. With no object type
its unscoped arm answers `NotDangerous`, which would state that access nobody examined is safe: the
precise failure `PermissionAssessment`'s four states exist to prevent. So the wording marks that
item as unnamed and the shell refuses to classify it. It is shown, it is counted, and it carries no
opinion in either direction.

This is the same shape as `S-53`'s trap about a GUID that resolves to nothing versus a GUID nobody
looked up. A verdict machine's default answer is dangerous wherever something reaches it that it was
never meant to see.

### Not-established moved for the same reason the mark did

An unworded bit used to grey the whole `Right` cell. With several rights on a row that meant one
line reading *we could not read this* over rights the classifier had just called a takeover — the
same cell asserting both. It now greys only the line it is about.

`F-S52-4` still holds and this strengthens it: what was read and what it grants are separate
statements. The principle turned out to apply twice, and the second application was only visible
once the first had been made.

---

## What this session leaves behind

**Built:** `PermissionRight`, per-right wording and classification, `PermissionRightViewModel`, a
derived entry verdict, the `Right` cell rewritten as a marked list, the generic-rights guard, and
`0076`. **1,669 tests, at `build AA`.**

### A refusal worth writing down

**The row was not split into one row per right.** It is the obvious way to make a mask a list, and
it is wrong: an access control entry is what the directory holds, what canonical order applies to,
and what an administrator removes. Rows per right would show a list that does not exist in the
object and that nobody can act on. Only the mark moved.

### Findings

- **`F-S55-1`** — **A safety net can be removed by a change that never touches it.** Nothing edited
  the generic-rights expansion; Option C changed *who decides which bits are judged*, and that alone
  turned a covered case into an uncovered one. Worth a habit: when a component starts choosing the
  inputs to another, ask what the second used to correct for.
- **`F-S55-2`** — **Three repository gates caught real gaps in this work and all three were
  right.** `SurfaceRegisterTests` and `SecurityDocumentationTests` failed on `PermissionRight` being
  public and undocumented; `DecisionIndexTests` failed on `0076` not being in `DECISIONS.md`. None
  was suppressed. That is now four sessions running (`F-S53-4`) in which the gates found something
  real, and every one of them was a documentation gap rather than a code defect — which is what
  those gates are for.
- **`F-S55-3`** — **`F-S52-1` recurred a third time and the recorded fallback worked unchanged.**
  `replace_string_in_file` refused `Views/Sections/ObjectSectionTemplates.xaml` while `get_file` and
  `grep_search` read it. Fragment file plus `[System.IO.File]` with absolute paths, byte-order mark
  detected and written back, both anchors asserted present and unique before replacing, result
  checked for mojibake and handed to the XAML compiler. Two further notes: **the terminal mangles
  multi-line commands**, so the script must be written to a file and run with
  `-ExecutionPolicy Bypass`; and the scripts are one-shot and were deleted, unlike `S-51`'s debris.

### Agreed and not built

The owed list, unchanged in order and not started:

- **Surfacing `HasCapturedEntries`**, so a bundle captured without a schema stops looking fully
  resolved. `S-53` built it and nothing reads it.
- **The base-schema disagreement finding** from [`0014`](../../decisions/0014-capture-reads-the-schema-partition.md),
  which the evidence now supports and nothing computes.
- **`F-S51-1`** — the `gPLink` option flags. **`MS-GPOL` has still not been read**, so *enforced* —
  the one fact that cannot be blocked further down — remains invisible.
- **`F-S50-2`** — `trustee.unresolved_reason` is still never written by capture.
- **`primaryGroupID` and `memberOf` as principals.** Still `515` and a list of distinguished names.

And carried from `S-52`:

- **A per-principal assessment.** *In combination* is now marked on the right that is a component,
  which makes it more obvious that nothing asks whether one principal holds the whole replication
  set — the question that makes DCSync. `0016` says who owns it.
- **The window has not been looked at since this change.** A row with three dangerous rights now
  wears three marks where it wore one. That is the intended reading, and `S-51` records that looking
  is how the data bugs get caught.
- **Five one-shot scripts are still untracked in `next/tools/`** — `s52-apply-template.ps1`,
  `s52-column.fragment.xml`, `s52-strip.fragment.xml`, `s53-apply-columns.ps1` and
  `s53-apply-layout.ps1`. `F-S52-1` says these are not kept, and their anchors were consumed when
  they were applied, so they cannot be run again. Left in place rather than deleted because they are
  untracked and belong to earlier sessions; `S-52`'s four scratch `.txt` files in `Views/Sections`
  are gone, so this is the same debris in a new place.
