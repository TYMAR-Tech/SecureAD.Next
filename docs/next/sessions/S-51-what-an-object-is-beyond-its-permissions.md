# S-51 — What an object is, beyond its permissions

**Status: closed. All four steps are built — see *What this session leaves behind*.**

Written 2026-08-18 as `S-50` closed. Read
[`S-50`](S-50-the-object-view-and-what-a-permission-says.md) — its *What this session leaves
behind* is this session's starting state — then
[`S-8-captured-attribute-catalogue`](../S-8-captured-attribute-catalogue.md) and
[`how-the-app-looks`](../../areas/how-the-app-looks.md).

**The tree is at `build N`.** The object view is on screen and judged: the left column swaps between
the directory tree and the object's sections, permissions read left to right, and every section but
Overview, Permissions, Evidence and Other captured values says it is not built.

---

## Why this

`S-50` built a place to put what a run captured and then discovered that **nothing in this product
can read an attribute value out of a bundle.** Only the security descriptor is readable. So an
object view exists, its sections are chosen correctly by class, and eight of them are honest
placeholders.

The bundle already holds everything they need. The reader is the missing piece, and it is the same
shape as `ObjectPermissionsReader`, which `S-50` proved out.

---

## What exists

| | |
|---|---|
| `ObjectSectionCatalog` | Which sections a class gets, and which attribute each is responsible for. Gated: an attribute is shown or declared not shown, with a reason |
| `ObjectViewModel` | A host over an ordered section list. A section is a type and a data template; adding one touches the catalogue and the template dictionary |
| `ObjectPermissionsReader` | The pattern to copy — owner, states, entries, trustees resolved against captured `objectSid` |
| `captured_object` and the value tables | Single-valued attributes as columns, multi-valued as one table each, both derived from the catalogue |
| **no reader of an attribute** | **the gap** |

---

## Decided already — do not re-open

**Sections are chosen by class, never by whether a value arrived.** An attribute that did not arrive
and one the object never had are the same emptiness on the wire, so hiding a section because it is
empty would hide *we were refused this*. `docs/decisions/0022` and `0002`.

**Curation may not hide a captured value.** Capture requests every attribute of every object
whatever its class, so an object can hold a value its class does not account for. Anything no
section claims appears under *Other captured values*, and only when it has one.

**The Live sections are not built.** This product reads sealed evidence, not directories.

**Nothing renders an empty result**, and nothing here is a verdict.

---

## Steps

1. **Read an attribute.** Single-valued and multi-valued, for one object, with the value's stored
   form available beside its worded one. Proved by tests.
2. **Overview and Account**, against real values. This is where `userAccountControl` gets worded and
   where the reveal earns itself.
3. **Catalogue version 3.** Add `lastLogonTimestamp`, `whenCreated`, `whenChanged`,
   `userPrincipalName`, `description`, `accountExpires`; **never `lastLogon`** — `S-50` records why.
   The section gate will fail the build until each one is placed, which is the gate doing its job.
4. **The remaining sections**, in the order an operator meets them: Membership, Delegation, Group,
   LAPS, Password readers, Linked policies, Policy.

**Each step is looked at on a running window before the next begins**, and the build marker in
`ShellWindow.xaml` is bumped every time — it is at `build N`.

---

## Verify against Microsoft Learn

**It has now paid three times.** `WRITE_OWNER` was labelled with the file system's word until Learn
said otherwise. The Scope column was written against Learn's statement that the directory service
treats every object as a container, which is why it does not talk about folders and files. And
`lastLogon` was refused because Learn says it is not replicated — a capture reading one controller
per domain would have reported one controller's view as a domain fact, and every stale-account
judgement built on it would have been wrong in a way nothing on screen could reveal.

Owed next, and none of it verified yet:

- **`userAccountControl`**, bit by bit. Every flag this product words, against Learn's own table.
  This is the one where being wrong is invisible: a wrong bit renders as a confident *Disabled*.
- **`pwdLastSet`, `accountExpires` and the LAPS expiry timestamps** — which are `FILETIME`, which
  are not, and what `0` and `-1` mean in each. `accountExpires` uses two sentinels for *never*.
- **`groupType`**, for group scope and whether a group is a security group.
- **`sIDHistory`**, and what it means for a principal's effective access.

---

## What `S-50` left open

- **`F-S50-2`** — `trustee.unresolved_reason` is never written by capture, so *why* a SID did not
  resolve is blank in every bundle. Small, capture-side, and it finishes something `S-50` promised.
- **`F-S50-4`** — nothing proves a template reads the state a view model publishes. A mark was lost
  in a rewrite with a green build.
- **`F-S50-5`** — the editing tool cannot see pre-existing `.xaml` and will silently create empty
  files at the repository root if given a solution-relative path. **Read this before editing XAML.**
- **Step 3 of `S-50`** — the *Highlight risky permissions* toggle, off by default, marking and never
  filtering. The first time `DangerousPermissionClassifier` runs against a bundle. It is small and
  it is not this session's subject; it can be taken first or left for its own.
- The `S-49` leftovers `S-50` did not reach: `F-0049-1`, Runs being redundant, the unindexed listing
  paths, the mutation test that damaged a repository file, and the polish list.

---

## What this session leaves behind

**Built:** `ObjectAttributesReader` and `BundleReader.ReadObjectAttributes`, the first thing in this
product to read an attribute value out of a bundle (18 tests). `UserAccountControlWording` (40),
`DirectoryTime` (19), `GroupTypeWording` (14) and `PolicyLinkList` (13), each verified against
Microsoft Learn. Catalogue version 3 and schema version 5. Every section on the object view now
shows something: Overview and Account against real values, seven more through one shared
`AttributeSectionViewModel`, and Linked policies through a reader of its own. **1,572 tests pass, at
`build U`.**

**Existing bundles are refused.** Schema 5 against a build that reads 4. Per
[`0001`](../../decisions/0001-no-backward-compatibility.md) they are recaptured, never migrated.

### One decision was re-opened, on evidence

**`whenChanged` is refused**, though `S-50` agreed to capture it. Microsoft documents it as **not
replicated** — the same property that got `lastLogon` refused. Two controllers can disagree about
when an object last changed, and this product reads one controller per domain, so it would report
one controller's opinion as a fact about the object. Both refusals now live in
`CapturedAttributeCatalog.NotCaptured` with their reasons, because a refusal that is not written
down is indistinguishable from an oversight and both of these will be proposed again.

### What Learn was worth this session

It paid four more times, and every one of them was a mistake that would have rendered as a confident
statement rather than as an error:

- **`accountExpires` has two values meaning *never*** — `0` and `9223372036854775807`. Handling one
  and not the other renders the other as an expiry in **1601** or in **30828**, and both read as a
  lapsed account nobody revoked.
- **`pwdLastSet` of zero is not a date.** It is how the directory records *the password must be set
  at the next logon*, and those accounts are exactly what an auditor is hunting.
- **`groupType` arrives negative.** The security bit is `0x80000000` in a signed 32-bit field, so an
  ordinary global security group is `-2147483646`. A reader parsing it unsigned rejects every
  security group in the forest.
- **`gPLink` order is the reverse of precedence.** Learn: read left to right, applied in reverse. A
  list shown in stored order tells an operator the wrong policy wins, on exactly the containers
  where two policies disagree.

### Findings

- **`F-S51-1`** — **The `gPLink` option flags are not worded, because Learn does not give their
  values.** The attribute's own page says only *a sorted list of Group Policy options, each option
  is a DWORD*. A link can be **disabled** or **enforced**, and enforced is the one that cannot be
  blocked further down — so this screen currently cannot show the strongest fact about a policy
  link. `MS-GPOL` documents the values; nobody has read it. Until then the number is shown as stored
  and marked *not worded by this build*. `gPOptions` is untouched for the same reason.
- **`F-S51-2`** — **A section could claim an attribute capture never requests**, and every row would
  read *Not in this bundle* on every object in every forest forever — indistinguishable on screen
  from an attribute the run was refused. `ObjectSectionCatalogTests` now gates it in both
  directions, along with a gate that every shown attribute has a written label.
- **`F-S51-3`** — **`F-S50-5` is worse than recorded.** The editing tool cannot see pre-existing
  `.xaml`, so XAML is edited through PowerShell — and a here-string in that shell **corrupted
  `ObjectSectionTemplates.xaml` mid-session**. Because that file is *untracked*, `git checkout` could
  not restore it and it was repaired by hand. Separately, a `Get-Content`/`Set-Content` round trip
  **double-encoded every em dash in `CONCEPT-REGISTRY.md`**. Rules that now hold: XAML goes through a
  temp file, never a here-string; prose files are edited with the file tool, never round-tripped
  through PowerShell.
- **`F-S51-4`** — **`FieldLabel` sets a fixed `Width`.** Used label-above-value, WPF centres a child
  that has an explicit width and default alignment, so every label floated ~375px right of the value
  it labelled. On screen for two builds. The style was written for label-*beside*-value rows and
  says so; nothing stopped it being used the other way.
- **`F-S51-5`** — **Ages must be measured against the run, not against today.** A bundle is sealed
  evidence: a password last set six days before a capture is a fact about that forest and stays one.
  `ObjectAttributes` now carries `CapturedUtc` for this. Anything later that words a duration has the
  same obligation.

### Agreed and not built

- **The counters and the red rows** from the owner's reference screens — *Dangerous*, *Control*,
  *Findings*. Nothing computes them, and **a zero printed where nothing has looked** is the failure
  [`0002`](../../decisions/0002-absent-view-means-degraded-run.md) exists to prevent. They arrive with
  the classifier, not before.
- **`primaryGroupID` and `memberOf` as principals.** Still `515` and a list of distinguished names.
  Both need the shell to resolve a SID or a DN against the bundle, which is a new seam rather than a
  wording.
- **The UI pass.** Deferred deliberately, and the owner's reasoning is recorded: UI debt here is
  cheap because a section is a view model plus a data template picked by type, while data debt is
  baked into every bundle captured before it is found. The condition attached: **fix layout whenever
  it blocks reading the data**, because looking at each step on a running window is how the data
  bugs get caught.
- **`F-S50-4`, `F-S50-2` and `S-50` step 3** — all still open. This session added four templates and
  roughly forty bindings to the first of them.
