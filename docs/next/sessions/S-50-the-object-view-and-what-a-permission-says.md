# S-50 — The object view, and what a permission says

**Status: run 2026-08-18. Steps 1 and 2 are built; step 3 is not.** The object view is on screen
at `build N` and the owner has judged it. What it leaves behind is at the end of this file, and
`S-51` picks it up.

Agreed with the owner on 2026-08-18 at the end of `S-49`. Read
[`how-the-app-looks`](../../areas/how-the-app-looks.md) and
[`what-a-permission-means`](../../areas/what-a-permission-means.md) before anything else.

---

## Why this

Clicking a row in the Assets grid does nothing. It is the last unbuilt step of `S-49`, and
permissions are the substance of the audit: everything the judgement half will eventually say is
computed from access control entries. The machinery is built and tested and has never been run
against a bundle.

**The owner's framing:** *"The real thing I want them to focus on is the findings, but since we do
have all the permissions it would be a great secondary use of this tool to help them understand
what permissions are on an object."* So this is a reading tool, not a verdict.

---

## What exists

| | |
|---|---|
| `PermissionWordingWriter` | An entry in words — `Full control`, `Write member`, `Modify owner`. Built in `S-49`, 15 tests |
| `Sid` | SID between its two forms, so a trustee can be matched to a captured object |
| `DangerousPermissionClassifier` | Judges one entry. Golden-tested against the predecessor. **Never yet run against a bundle** |
| `SchemaGuidCatalog` | GUID to name, for extended rights, property sets, validated writes and classes |
| **no reader of a descriptor** | **the gap** |

The bundle holds: `security_descriptor` (owner, `dacl_state`, `dacl_completeness`,
`dacl_was_canonical`, `is_dacl_protected`), `ace` (type, trustee, mask, both object-type GUIDs,
inherited flag, inheritance and propagation flags, ordinal), `trustee` (SID and why it did not
resolve), `security_descriptor_error`, `unreadable_security_descriptor`.

---

## Decided already — do not re-open

**The layout is the predecessor's, and it works in production.** Principal, then that principal's
entries, with columns **Right, Type, Scope, Inheritance**. The owner has used this daily.

**One full-width table grouped by principal, not two panes.** Groups collapsed by default; the
header carries principal, domain, rights summary and entry count. This replaces the predecessor's
left pane *and* its double-click pop-out window, both of which existed because two panes left no
room for the entry table on a laptop. Decided 2026-08-18 against the owner's screenshots.

**Classification is a toggle, off by default, labelled "Highlight risky permissions".** The owner
is not certain the predecessor was right to classify at all. It **marks and never filters** —
filtering would let a reader conclude the marked few are all there is. The label admits it is an
opinion.

**Nothing renders an empty result.** A null DACL grants everyone everything, an empty one grants
nobody anything, and an unreadable one is unknown. All three show as "no entries" in a viewer that
does not distinguish them, and one of the three is a finding.

---

## What this must show that the predecessor could not

1. **Why a SID did not resolve.** The owner's screenshot has a bare
   `S-1-5-21-…-25601` holding Full Control with no explanation — an orphaned SID, as it turned out.
   `trustee.unresolved_reason` already says which of four reasons it is.
2. **That inheritance is blocked**, from `is_dacl_protected` — the explanation for an ACL that
   looks surprisingly short.
3. **That the entry order is not canonical**, from `dacl_was_canonical`. Windows evaluates in
   stored order, so a deny after an allow may never apply and the object is more open than it reads.
4. **That the DACL was truncated**, from `dacl_completeness`.
5. **The three empty states**, kept apart.

---

## Steps

1. **Read a descriptor.** Owner, states, entries, trustees resolved against captured `objectSid`.
   Proved by tests.
2. **The object view.** Selecting a row in the grid replaces it; the tree stays; a way back.
   Overview first, then Permissions.
3. **The toggle.**

**Each step is looked at on a running window before the next begins**, and the build marker in
`ShellWindow.xaml` is bumped every time — it is at `build J`.

---

## Verify against Microsoft Learn

**The owner asked for this by name on 2026-08-18, and it has already paid.** The wording layer was
checked against Learn the day it was written: every mask value was confirmed, and one label was
wrong — `WRITE_OWNER` had been called *Take ownership*, which is the **file system's** word. The
directory's is **Modify owner**, and both tools sit on the same administrator's screen.

This is the anchor problem `F-S44-2` names: a set of checks can be internally consistent and
anchored to nothing outside itself. Tests prove the code does what the test says. **Only Learn
proves the words and the values are the directory's.** Check anything asserted about the directory
against it, and record what was confirmed.

Owed next: the inheritance flags behind the **Scope** column — `CONTAINER_INHERIT_ACE`,
`OBJECT_INHERIT_ACE`, `INHERIT_ONLY_ACE`, `NO_PROPAGATE_INHERIT_ACE` — and how they combine with
`inherited_object_type_guid` to produce *This object*, *This object and all descendants*, or
*Descendant user objects*. Nothing has verified those yet.

---

## What `S-49` left open

- `F-0049-1` — the only `RadioButton` style is the rail's, invisible on a light screen. Half fixed.
- **Runs is redundant** and could live under Home — the owner, 2026-08-18. Not acted on.
- **The listing is unindexed** on two paths: one-level filters on `parent_dn`, and the name
  ordering is an expression. Needs a bundle of millions to measure against.
- **A mutation test damaged a repository file** it could not restore while the file was open.
- Polish the owner listed: tree icons; a search box replacing the *Assets* title; grouping the
  repeated *"a partition this product does not read"* entries; font size, product-wide.

---

## What this session leaves behind

**Built:** `ObjectPermissionsReader` and `BundleReader.ReadPermissions`, the first thing in this
product to read the descriptor half of the schema (20 tests). `PermissionScopeWriter`, the Scope
and Inheritance columns, verified against Learn (12 tests). `ObjectSectionCatalog` and its gate (18
tests). `ObjectViewModel` as a host over class-driven sections, with the section list in the left
column where the tree was. 1,433 tests pass.

### Two decisions were re-opened, both because a premise failed

**The object view replaces the tree, not the grid.** The brief said the grid is replaced and the
tree stays, decided when the object view was assumed to be a permissions table. The predecessor's
`ObjectDetailWindow` is 1,311 lines carrying **sixteen** sections behind a left rail. Two tabs in a
60%-wide pane cannot grow to that, so the left column now swaps: tree while listing, sections while
reading an object.

**Permissions reads left to right after all** - principal list, entries beside it. The brief
rejected two panes because two panes *plus the tree* left no room for an entry table on a laptop.
The object view took the tree's place, so that width came back and the constraint is gone. The
judgement was never overruled; the thing it was judging changed.

### Findings

- **`F-S50-1`** - `operatingSystem`, `ms-Mcs-AdmPwdExpirationTime` and
  `msLAPS-PasswordExpirationTime` have been captured on every computer in every bundle since
  2026-08-13, for `SEC-091` and `SEC-092`, which do not exist. Nothing could show them, and nothing
  said so. The section gate now makes that state unreachable silently and the LAPS section makes
  the three visible. **The general risk remains**: `CapturedAttributeCatalogDocumentationTests`
  proves an attribute names a consumer in prose, and its own remarks call the unchecked direction
  the one with the one-way door in it.
- **`F-S50-2`** - **`trustee.unresolved_reason` is never written.** The column, its four-value
  check, the reader and the screen all exist; `BundleWriter.TrusteeId` inserts `(trustee_id, sid)`
  and nothing else. So *why* a SID did not resolve - item 1 of what this view must show that the
  predecessor could not - reads as *nothing this run captured holds this identifier* against every
  bundle written today. Capture-side, not reader-side.
- **`F-S50-3`** - **The per-class lists in `CapturedAttributeCatalog` justify capture; they do not
  scope it.** Capture asks every object for every attribute whatever its class. This session
  misread that exactly as a previous one did, and the code already carries a warning about it. The
  class-driven section list is therefore a product judgement - *a user is not a thing LAPS applies
  to* - and never a claim that something was not asked for. `Other captured values` is the safety
  valve, so curation cannot hide a value the bundle holds.
- **`F-S50-4`** - **Nothing proves a template reads the state a view model publishes.** The
  *not established* mark on a permission entry was lost when the permissions template was rewritten,
  silently, with a green build and a passing test for the view model that produced it. Same blind
  spot as the four state marks that once all fell through to one.
- **`F-S50-5`** - **The editing tool cannot see pre-existing `.xaml`.** It edits `.cs` and any XAML
  it created this session; anything older returns *could not find file*. Given a solution-relative
  path it silently **creates empty files at the repository root** - two were created and deleted
  during this session. XAML was edited through PowerShell instead.

### Agreed and not built

- **Catalogue version 3**, on the owner's decision: add `lastLogonTimestamp`, `whenCreated`,
  `whenChanged`, `userPrincipalName`, `description`, `accountExpires`. `description` earns its place
  because credentials are found in it. **`lastLogon` is refused**: Learn's *Last-Logon attribute*
  page states it is not replicated and must be read from every controller in the domain, and capture
  reads one - so it would report one controller's view as a domain fact. `lastLogonTimestamp` is
  replicated but by design lags 9-14 days, and anything rendered from it must say so.
- **Raw values**, agreed in the narrow form: reveal the stored value where this product
  *interpreted* one - bit fields, timestamps, SIDs, GUIDs - and stay quiet where it transcribed.
  `userAccountControl` is the case that matters: if a bit mapping is wrong, the screen says
  *Disabled* about an enabled account and nothing visible contradicts it.
- **Step 3, the classification toggle.** Untouched. It is still the first time
  `DangerousPermissionClassifier` runs against a bundle.
- **The Live sections are dropped**, on the owner's decision. Live effective access, live
  inheritance and live ACL compare read a directory at inspection time; this product reads a sealed
  bundle on a machine that may never have seen the forest.
