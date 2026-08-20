# S-52 — The first thing that judges

**Status: closed. `S-50` step 3 is built and `F-S50-4` is closed — see *What this session leaves
behind*.**

Written 2026-08-18 as `S-51` closed. Read
[`S-51`](S-51-what-an-object-is-beyond-its-permissions.md) — its *What this session leaves behind* is
this session's starting state — then
[`S-4-dangerous-permission-classification`](../S-4-dangerous-permission-classification.md) and
[`0002`](../../decisions/0002-absent-view-means-degraded-run.md).

**The tree was at `build U`, 1,572 tests green.** Every section of the object view showed something,
and nothing on any screen was a judgement.

---

## Why this

Everything built so far **reports**. A run states what it read, an object states what it holds, a
permission states what it grants. `DangerousPermissionClassifier` has existed since `S-4`, is
golden-tested against the predecessor, and **had never been run against a bundle**.

This session is the first time the product says *this one is dangerous*. That is a different kind of
claim from everything before it, and the two ways it can go wrong are both invisible on screen: a
verdict nobody asked for, and a zero where nothing looked.

---

## Decided already — do not re-open

**The toggle is off by default, and it marks and never filters.** `S-50` settled both. Filtering
would let a reader conclude the marked few are all there is, and the entries this build *cannot*
classify are exactly the ones a filter would hide.

**Nothing renders a zero where nothing has looked.** [`0002`](../../decisions/0002-absent-view-means-degraded-run.md).

**A view model may not hold a brush.** It names a state; the template decides what that looks like.
`ShellMvvmGateTests` fails the build otherwise.

---

## What the owner settled this session

| | |
|---|---|
| Which verdicts are marked | **Only `Dangerous` and `DangerousInCombination`.** `NotDangerous` and `CannotClassify` get no mark at all |
| What colour | **Red**, for a takeover, and `0056` decision 5 amended by a record of its own |
| The Findings counter | Shown, with an explicit *not computed* state, **never a number** |
| Counter scope | The whole object, once, above the two panes |
| What *Control* counts | *"I don't remember how it was used, you'd have to read my old code"* — so it was read |

**`Control` was `ControlEdges.Count`.** `src/SecureAD.UI/ObjectDetailWindow.xaml:268`. A control edge
is an **escalation-graph derivation** — `D1`-`D9`, `EscalationEdgeWeights`, `ControlType` — computed
across a whole forest, and **not an access control entry classification at all**. Nothing in the new
tree derives them. So `Control` cannot be computed by the classifier however the screen is wired, and
it takes the same *not computed* treatment as `Findings`. Had this not been read, the obvious guess —
*entries granting WriteDac or WriteOwner* — would have produced a plausible number under a label that
has always meant something else.

---

## What this session leaves behind

**Built:** the *Highlight risky permissions* toggle, off by default. `PermissionRisk`,
`PermissionCounter`, per-entry classification in `PermissionEntryViewModel`, the counter strip and the
Risk column. **1,615 tests pass, at `build V`.**

**The classifier now runs against sealed evidence**, for the first time since it was written in `S-4`.

### The counter strip states what it cannot answer

Five counters. *Entries* is always computed. *Dangerous* and *In combination* are computed only while
the toggle is on and otherwise say so and point at the toggle. *Control* and *Findings* **can never be
computed by this build** and say why — a control edge is derived across a forest, a finding is a
rule's verdict, and neither layer exists.

A counter with nothing behind it shows an em dash, the words *not computed*, and its reason in a
tooltip. **A dash rather than a blank**, because a blank cell reads as a rendering fault and an
operator who thinks the screen is broken will guess at what belongs there.

**The Risk column is absent entirely until the toggle is on.** A column headed *Risk* standing empty
on every row reads as *no risk* — the same failure as the zero, in a different shape.

### `F-S50-4` is closed

`ViewBindingGateTests`, and it **fired on its first run against the real shell**. Five hits, every one
a defect in the scanner rather than in the product, each confirmed by reading the source before
anything was loosened:

- A binding written across two lines whose `RelativeSource` is on the second. Read a line at a time,
  the first half looks like a plain path.
- `{Binding Objects/}` — WPF's **current-item syntax**, which names `Objects` and was read as a
  property called `Objects/`.
- `Precedence`, `Order`, `Options` — `PolicyLink` is a **kernel record**, and an item template binds
  domain records perfectly legitimately.

It scans in two directions because the two failures differ. Every path must name something published
— that catches a **rename**. The facts that matter must still be named by a template — that catches a
**deletion**, which no path check can see, and a deletion is precisely what `F-S50-4` recorded.

### Findings

- **`F-S52-1`** — **`F-S51-3` is not about XAML, it is about which files the editing tool can see.**
  `replace_string_in_file` edited `Themes/StateMarks.xaml` without complaint and then refused
  `Views/Sections/ObjectSectionTemplates.xaml` and `Views/ShellWindow.xaml` with *could not find file
  in the current workspace* — while `get_file` and `grep_search` read all three. The rule that holds:
  attempt the edit, and on that error fall back to fragment files plus
  `[System.IO.File]::ReadAllText`/`WriteAllText` with the byte-order mark detected and written back.
  **Never a here-string.** The shape that works: write the replacement text to its own file, assert
  in the script that each anchor exists **and is unique** before replacing, and check the result for
  balanced tags and mojibake afterwards. The scripts themselves are one-shot — their anchors are
  consumed once applied — so they are not kept.
- **`F-S52-2`** — **`.NET`'s working directory is not PowerShell's.** `[System.IO.File]` resolved a
  relative path against a directory two `cd`s ago and reported a file as missing that was there.
  Absolute paths only, in anything that reaches the disk through `System.IO`.
- **`F-S52-3`** — **The shell has one boolean-to-visibility converter and no inverting one.**
  Expressing *not* needed either a second converter or a published property. `IsNotComputed` was
  published, because a converter is a decision about what an operator sees in a place no test reads.
- **`F-S52-4`** — **`State` and `Mark` are separate on purpose, and it would be easy to merge them.**
  An entry can be fully worded and be a takeover, or half-worded and harmless. Folded into one column,
  an unworded access mask bit and a granted takeover would reach the screen as the same mark.

### Agreed and not built

- **`primaryGroupID` and `memberOf` as principals.** Still `515` and a list of distinguished names.
- **`F-S51-1`** — the `gPLink` option flags, still unworded. **`MS-GPOL` has not been read**, so
  *enforced* — the one fact that cannot be blocked further down — is still invisible.
- **`F-S50-2`** — `trustee.unresolved_reason` is still never written by capture.
- **A per-principal assessment.** *In combination* counts components and nothing asks whether one
  principal holds the whole replication set, which is the question that makes DCSync. It is a question
  about a principal, not an entry, and `0016` says who owns it.
- **The window has not been looked at.** Every step before this one was reviewed on a running window
  and this one has not been. The classifier's verdicts against real evidence are unreviewed, and
  `S-51` records that looking is how the data bugs get caught.
- **Four scratch `.txt` files** remain untracked in `Views/Sections`, debris from `S-51`'s workaround.
