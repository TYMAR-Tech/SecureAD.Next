# S-59: Checking S-58's repairs

**Your task is to check three commits, not to extend them.** Fixes are out of scope unless this
brief names them. If you find something wrong, record it and stop — the value of this session is an
independent reading, and a session that starts fixing stops reading.

---

## Why this session exists

`S-58`'s later work was done by one session that also wrote its own verification, its own
documentation and its own commit messages. That session was told, by the brief it inherited, that
*a fix written by the session that produced the conclusions is hard to check against them*. It then
demonstrated the point: **it stated a wrong claim about GUID presence confidently, across two
commits and several reports, and only caught it when it finally measured.** Three other claims it
made were also wrong first time — a missed-place count, a severity, and a batching premise.

Every one of those was caught by looking at data or at sources. None were caught by re-reading its
own reasoning. That is the method this session should use.

## The baseline

Branch `explore/design-challenges`, commit `394ee420`. Suite green at **1,753**, tree clean.
`next/tools` holds three real scripts and nothing else.

Lab bundle: `Lab Databases/ad.lab-20260819-232425`. It opens under this build. Read it with
`Microsoft.Data.Sqlite` from the built CLI output and **pwsh**, not Windows PowerShell.

## The three commits

| Commit | What it did |
| --- | --- |
| `919accea` | Added `ApplicationData` to the ACE hash; `AceCanonicalization.Version` 2 → 3 |
| `120c76d7` | `BundleReader.Open` refuses a bundle whose `canonicalization_version` differs |
| `394ee420` | `ObjectPermissions` reads the stored DACL from `raw_bytes` instead of the `ace` table |

---

## What to check, and why each is doubtful

### 1. The version 3 golden hashes — `919accea`

Eight constants in `GoldenAceHashTests` moved. The method was: build an independent calculator of
the written recipe, prove it reproduces all eight **version 2** values under the version 2 recipe,
then use it for version 3. That is the method version 2 itself used and it is sound.

**The doubt is that the same session built the calculator, ran it, and judged the result.** The
calculator was deleted, so nothing survives to re-check it against. Rebuild one independently from
the recipe as written in `AceNormalizer.ComputeAceHash`'s remarks and `S-1`'s *How a hash is built*,
and confirm the eight constants. If your recipe and theirs disagree, **that is the finding** — do
not adjust either.

The recipe should be ten pipe-delimited fields, UTF-8, SHA-256, lowercase hex, with application data
as lowercase hex and empty for every golden case.

### 2. The refusal's scope — `120c76d7`

`BundleReader.Open` refuses when any distinct `canonicalization_version` differs from the build's.
**A bundle holding no descriptors opens**, on the reasoning that it holds no hash that could be
stale.

That carve-out was chosen unilaterally and no document requires it. Check whether it is right. The
opposing case: a run that captured no readable descriptor is exactly the run whose evidence is most
in doubt, and `0002`'s zero-where-nothing-looked defect is this repo's recurring failure.

Also check the refusal is not too broad. `raw_bytes`, DACL states, trustees and every ACE field
remain valid under a version change; only the hashes cannot be recomputed. Refusing the whole bundle
is consistent with `SchemaVersionUnsupported` — but that gate exists because the *tables* cannot be
read, which is not the case here.

### 3. Re-parsing on read, generalised from one forest — `394ee420`

The design fork — re-parse `raw_bytes` versus widen the projection — was settled by measuring **one
lab bundle**: 363 distinct descriptors, 611 KB, 8,361 objects. On those numbers re-parsing is free.

**The generalisation is untested.** Deduplication collapsed 8,361 objects onto 363 descriptors — a
23:1 ratio that a large or heavily delegated forest may not show. `ObjectPermissions.Read` parses
one descriptor per call and `AssetsViewModel` calls it per selected object, so the per-screen cost
looks safe; satisfy yourself that nothing calls it in a loop over a page or a subtree.

Worth checking directly: is there any caller that reads permissions for many objects at once?

---

## Findings raised and deliberately not actioned

Check these are real before anyone builds on them. Two were raised by the session that also
mis-stated the GUID claim.

- **`F-S58-12` is incomplete, and its scope grew three times.** The early-stop claim was reported as
  corrected in six places. At least three more live places were then found: `BundleSchema.cs:499`,
  `ParsedSecurityDescriptor.cs:32`, `S-16-the-bundle.md:222`. **Nobody has done a systematic sweep**
  — each was found incidentally. Do the sweep and get a real count.

  **The correction itself may also be wrong.** `AceCanonicalization` now says flatly that AD
  examines every ACE to the end. That is MS-ADTS 5.1.3.3.2, *Checking Simple Access*. `S-56` R20
  states that control access rights and validated writes **do** terminate at the first applicable
  ACE, and warns explicitly against applying the general early-stop algorithm to all AD rights. The
  flat wording risks being a second over-generalisation replacing the first. **This needs the
  owner's ruling before anything is edited.**

- **`SchemaVersionUnsupported` has no test.** Zero matches in the test project. The gate that
  `CanonicalizationVersionUnsupported` was modelled on would survive being deleted.

- **`BundleWriter:659` writes the constant, not the data.** It writes
  `AceCanonicalization.Version` rather than the version carried on the ACEs being written. Harmless
  while they cannot differ, but the column's comment now claims it records what produced these
  entries, and it records what the build is.

- **`F-S58-8`** — a public enum member crossed a registered surface with no gate firing. Same shape
  as `F-S53-1`.

- **`F-S58-2`, `F-S58-4`, `F-S58-5`** — untouched by this work. `F-S58-4` is medium and open.

## What is settled — do not reopen

- Bundles are expendable; a re-audit is the accepted cost of a version change. The owner took that
  decision twice, deliberately.
- `#6`'s verdict is qualified, not withdrawn.
- `S-56` v4 R11 is verified and closed as `F-S58-13`.
- The two version numbers stay independent. `F-S1-1` records the coupling removed to keep them
  apart, and folding them would reinstate it.

## Blocked, correctly

- `#19` — needs MS-GPOL 2.2.2 read.
- `#17` — Undecided, and `S-57` is emphatic that this is a verdict.
- `S-56` R5's split — needs capture to collect forest functional level and `fDontStandardizeSDs`.
  **This is capture-side work, not schema work**, and it is the only remaining item that genuinely
  needs a schema change afterwards.

## Owner decisions outstanding

- `#12` — confidential access needs `READ_PROP` **and** `CONTROL_ACCESS`, possibly from different
  entries, so no per-entry view can state it. Needs the per-principal layer `F-S4-2` records as
  having no owner. A design decision about where a verdict lives, not a defect.
- `docs/history/S-21:35` says the canonicalisation version is *"currently `2`"*. It is 3. The file
  is a record of a past session, so correcting it edits history and leaving it leaves a false
  sentence. One line either way.

---

## How to work

- Treat every finding in `S-58` as a **claim with a source attached**, and check the source. Claims
  raised by the session that wrote them deserve more scrutiny, not less.
- Never assert what a previous session did without reading its commit message. `F-S58-9` was filed
  against a session that had documented its reasoning; the accusation was withdrawn only after the
  evidence turned up by accident.
- Measure before concluding. Every wrong claim in `S-58` was reasoned from a doc comment or from
  reading code, and every correction came from data.
- Throwaway scripts: ~20 lines, work in SQL where it can be, deleted before you finish.
- Report what you checked and what it showed, before what you did. Say plainly what you did not
  check.
