# S-53 — The schema the run already read

**Status: closed. See *What this session leaves behind*.**

Written 2026-08-18, continuing directly from
[`S-52`](S-52-the-first-thing-that-judges.md). Read its *What this session leaves behind* first, then
[`0014`](../../decisions/0014-capture-reads-the-schema-partition.md) and
[`S-3-schema-guid-catalogue`](../S-3-schema-guid-catalogue.md).

**The tree was at `build V`, 1,615 tests green.** The classifier had just been wired to the screen
for the first time.

---

## Why this

The owner looked at a running window — the thing `S-52` closed without doing — and asked two
questions about one screenshot.

> *"layout still needs work, and user should be able to move columns size. also, why do we have
> guids in the rights, we are querying the schema so shouldn't we know them"*

The second question was the important one, and the answer was **yes, we should, and we were throwing
it away**.

---

## What was wrong

`4828cc14-1437-45bc-9b07-ad6f015e5f28` is `inetOrgPerson`, a stock Active Directory class.

The screen resolved GUIDs against `SchemaGuidCatalog.Embedded` — a hand-written table of about a
hundred entries: 13 classes, 30 attributes, 37 extended rights, 15 property sets, 5 validated
writes. `inetOrgPerson` is not on it.

Meanwhile **capture had been reading the forest's schema the whole time.** `CapturePlan` enumerates
the schema naming context and deliberately reads it *first* — the code comment says *"a permission
naming a schema GUID means nothing until the schema"* is loaded — and every definition lands in
`captured_object` with `lDAPDisplayName`, `schemaIDGUID`, `rightsGuid` and `validAccesses`.

Nothing read them back. There was no reader, `BundleReader` had no method, and
**`SchemaGuidSource.Captured` — the enum member that exists to mark a forest-sourced name — was
never produced anywhere in the product.**

So `0014` was half built. It says the catalogue is *"one lookup over two layers — shipped and
captured — and every answer states which"*. Only one layer had ever existed, and every name on
screen silently claimed to be Microsoft's.

**Worst in a customer forest, not a lab.** A shipped table cannot contain a schema extension by
definition, so the attributes a customer added — the ones most likely to be delegated carelessly and
least likely to be understood — were exactly the ones rendering as raw GUIDs.

---

## What this session leaves behind

**Built:** `CapturedSchemaGuidReader`, `BundleReader.ReadSchemaGuids`,
`SchemaGuidCatalog.CapturedOver` and `HasCapturedEntries`, `PermissionVocabulary`, and the seam
carrying a catalogue from a bundle to a row. **1,634 tests, at `build W`.**

**No recapture was needed.** This was a read-side gap only, confirmed before any code was written —
which is what decided it was not a schema-version change.

### The two-layer lookup, as `0014` specified it

The forest's answer wins; the shipped table fills the gaps; every entry keeps its source. Entries
are deduplicated by GUID-and-kind and by name rather than concatenated, because both layers
certainly name `userAccountControl` and the name index is unique — a concatenating catalogue would
have thrown the first time it met a real forest.

`0014` also says a captured base-schema GUID that **disagrees** with the shipped value is a finding.
Nothing computes that, but the evidence for it now exists where it did not before.

### Three traps, all of which fail silently

- **`schemaIDGUID` is an octet string in the GUID's native little-endian layout.** Read as
  big-endian it produces a well-formed GUID that matches nothing, which on screen is
  indistinguishable from a forest that never defined the attribute.
- **`validAccesses` is the only thing separating three kinds** that share the extended-rights
  container. A reader assuming the container holds only extended rights mislabels every property set
  in the forest. An unrecognised value is treated as an extended right, which is the reading that
  grants most.
  **— Amended 2026-08-19; the last sentence is retired. See below.**
- **A GUID that resolves to nothing and a GUID nobody looked up render identically.** Hence
  `HasCapturedEntries`, so a screen can eventually say which kind of claim it is making.

### Amendment, 2026-08-19 — "the reading that grants most" was the right rule on the wrong axis

Recorded by the session that implemented `S-58` finding `#13`. **The paragraph above is left
standing deliberately.** It was a decision, not an oversight, and a decision record that quietly
loses the thing it decided cannot be audited afterwards.

**What was decided.** That an unrecognised `validAccesses` should resolve to
`SchemaGuidKind.ExtendedRight`, on the grounds that calling an unknown control access right a
property set would understate what a permission naming it hands over.

**What is wrong with it.** The reasoning is sound and it is applied to the wrong axis. "Grants
most" is the safe direction for a *severity* judgement, where being too loud costs an operator time
and being too quiet costs them the forest. But `validAccesses` does not answer *how bad is this*. It
answers *what kind of thing is this*, and per `S-56` R3 and R4 that is a factual classification:
R3 makes the kind of a GUID a function of `(GUID, mask bit)`, and R4 makes `validAccesses` the
normative field for which of the three kinds a `controlAccessRight` is.

A classification has no safe direction, because a wrong answer does not make the product louder or
quieter — it makes it **answer a different question**. Concretely, in
`DangerousPermissionClassifier.ClassifyScoped`, the kind selects the branch: a property set
mislabelled as an extended right is judged by `ClassifyExtendedRight` and never reaches
`ClassifyPropertySetWrite`, so the verdict is computed from the wrong rule entirely. The wrong
branch can be quieter than the right one, which is the precise failure "grants most" was chosen to
prevent.

**What replaces it.** A fourth kind, `SchemaGuidKind.Unclassified`, meaning *this build could not
say which kind this is*. It is the same separation `0002` and `0004` require everywhere else in this
product and that `PermissionVerdict.CannotClassify` already makes one layer up: *found nothing* and
*could not compute* are never rendered alike. Guessing the most permissive kind collapsed them.

**The second half of the original bullet stands unchanged.** `validAccesses` really is what
separates the three kinds, and a reader assuming the container holds only extended rights really
does mislabel every property set in the forest. Only the sentence about what to do when the value
is unrecognised is retired. The wording "the only thing that says which" has been softened to "the
normative field" in the source, per `S-57` — it is what the forest is *supposed* to publish, not a
guarantee that every forest publishes it correctly, and the unclassified case exists for exactly
that gap.

### Findings

- **`F-S53-1`** — **`0014` was specified in full and built in half, and nothing noticed for
  months.** `SchemaGuidSource.Captured` existed, was documented, was never constructed. An enum
  member that nothing produces is a design intention that reads as an implementation. Worth a gate:
  a declared source with no producer is either unbuilt or dead.
- **`F-S53-2`** — **`F-S52-1` recurred, and its rule held.** The editing tool refused
  `Views/Sections/ObjectSectionTemplates.xaml` and `Views/ShellWindow.xaml` while editing
  `Themes/StateMarks.xaml` without complaint, confirming the hazard is per-file rather than per
  extension. The fallback recorded in `S-52` worked unchanged: fragment files plus `[System.IO.File]`
  with the byte-order mark detected and written back, never a here-string, with every anchor asserted
  present and unique before replacement and the result checked for balanced tags and mojibake
  afterwards. The scripts are one-shot and are not kept.
- **`F-S53-3`** — **`System.IO` does not share PowerShell's working directory.** It resolved a
  relative path against a directory two `cd`s earlier and reported a file as missing that was there.
  Absolute paths only.
- **`F-S53-4`** — **Two repository gates caught defects in this work and both were right.**
  `NullDefaultGateTests` rejected a null-defaulted `vocabulary` parameter — a shortcut taken to avoid
  touching call sites, of which there turned out to be one. `SchemaGuidDocumentationTests` demanded
  the new members be documented. Neither was suppressed.

### The layout half

A `GridSplitter` between the principal list and the entry table, with minimum widths so neither pane
can be dragged shut; the divider had been fixed at 340px, chosen for a laptop, and an operator on a
wide screen could not reclaim it. `Right` takes the spare width and `Scope` sizes to its content.
Resize, reorder and sort are stated explicitly so a later edit cannot quietly drop them.
`RowHeight="NaN"` so a wrapped cell is not clipped invisibly.

This was UI debt `S-51` deferred, taken now under the condition attached to that deferral: **fix
layout whenever it blocks reading the data.**

### Agreed and not built

- **Saying when a name came from the shipped table only.** `HasCapturedEntries` exists and nothing
  surfaces it, so a bundle captured without a schema looks identically well resolved.
- **The base-schema disagreement finding** from `0014`.
- **`F-S51-1`** — `gPLink` option flags, still unworded; `MS-GPOL` still unread, so *enforced*
  remains invisible.
- **`F-S50-2`** — `trustee.unresolved_reason` still never written by capture.
