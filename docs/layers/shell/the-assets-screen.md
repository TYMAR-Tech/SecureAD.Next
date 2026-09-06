# The assets screen

**Code:** `next/src/SecureAD.Shell/ViewModels/AssetsViewModel.cs`, `AssetRowViewModels.cs`,
`ObjectViewModel.cs`, `ObjectSections.cs`, `ObjectSectionCatalog.cs`, `FactState.cs`,
`next/src/SecureAD.Shell/Services/IAssetSource.cs`, `BundleAssetSource.cs`
**Layer:** Shell — what one run captured and what the judging concluded about it: the directory as
its evidence can rebuild it, the objects in the part of it the operator selected, the findings, and
one object read in full.

[`ShellSection`](../../../next/src/SecureAD.Shell/ViewModels/ShellSection.cs) describes `Assets` as
*what the selected run captured*. The objects, the findings and an opened object are all that one
member: an object is opened from the grid rather than navigated to, so there is one screen here and
not three. The run is chosen on [`the home screen`](the-home-screen.md); the audit that produced it
is planned on [`the New Audit screen`](the-new-audit-screen.md).

As with every shell page, the types below are `internal` — the window exports nothing, and
`ShellSurfaceGateTests` fails the build the day it does.

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `AssetsViewModel` | The assets of one run: the tree, the objects, the findings, and which object is open |
| `IAssetSource` | How a bundle's tree, objects, permissions and findings are read |
| `BundleAssetSource` | Those reads, over a real bundle and the judgement beside it |
| `TreeNodeViewModel` | One container in the tree, and whether it was captured |
| `TreeGapViewModel` | Something the tree does not show, and why |
| `ListedObjectViewModel` | One object in the listing, as a grid row |
| `FindingRowViewModel` | One finding in the grid, as the judging stored it |
| `LapsComputerViewModel` | One computer in the LAPS inventory: both expiration dates, what it is capable of running, and — where a rule leaves it alone — which exclusion did it |
| `LapsCountViewModel` | How many computers are in one LAPS state across the whole container, including the states nothing is in |
| `RuleRowViewModel` | One rule: what it looks for, and what it did to this run — including the several ways it can report nothing |
| `ObjectPaging` | Where one page of a listing starts and how large it is |
| `FactState` | The three states every fact on this screen is drawn in |
| `ObjectViewModel` | One object opened in full: its sections, and which is showing |
| `ObjectSectionDefinition` | One section a class of object has, and the attributes that justify it |
| `ObjectSectionCatalog` | Which sections each class of object has |
| `ObjectSectionViewModel` | What every section of an opened object has in common |
| `OverviewSectionViewModel` | What this object is, said first |
| `AccountSectionViewModel` | What the directory records about an account |
| `PermissionsSectionViewModel` | Who can do what to this object |
| `EvidenceSectionViewModel` | What was captured about this object and what was not |
| `FindingsSectionViewModel` | What the judging concluded about this one object |
| `PolicyLinksSectionViewModel` | The policy linked at this container |
| `AttributeSectionViewModel` | A group of attributes shown together |
| `OtherValuesSectionViewModel` | Captured values no section claimed |
| `NotBuiltSectionViewModel` | A section named but not yet built, which says so rather than looking empty |
| `AttributeValueViewModel` | One attribute value, and whether it was captured at all |
| `PermissionVocabulary` | The words this forest uses for its own rights and classes |
| `PermissionCounter` | One count on the permissions section, and what it means |
| `PermissionRisk` | How much an entry on the permissions section is worth reading |
| `PermissionRightViewModel` | One right within a permission entry |
| `PermissionEntryViewModel` | One entry on an object's access control list |
| `PrincipalGroupViewModel` | The entries belonging to one principal, shown together |

<!-- TYPES:END -->

This table is the page's claim of ownership, bound in both directions against the internal types the
files above declare, by `ShellLayerTypesTests`.

The views over these — `AssetsView.xaml`, `FindingsView.xaml`, `ObjectView.xaml`,
`ObjectSectionList.xaml`, `GapsCard.xaml` and `Sections/ObjectSectionTemplates.xaml` — declare no
types of their own. What holds them is `ViewBindingGateTests` and `ViewResourceGateTests`, the
second of which exists because a view naming a resource the application never defined crashed the
product in front of the owner on 2026-08-26 with the build green and 2,410 tests passing.

---

## Four silences, kept apart

An empty screen is not one fact, and this screen refuses to draw four different ones the same way.

- **No run chosen** is a question the operator has not answered.
- **A capture is running** is a refusal with a remedy: wait. The bundle is not read at all while one
  is writing it.
- **A bundle that would not open** is a failure he needs to see, in the words the evidence layer
  used rather than reworded here.
- **A container that was read and holds nothing** is an empty container, which is a claim worth
  making.

Showing an empty list for all four would say *there is nothing here* in three cases where that is
not known to be true. That is
[`0002`](../../decisions/0002-absent-view-means-degraded-run.md) exactly, and it is the rule the
whole screen is built around.

---

## Nothing on this screen is ever established-bad

Every fact is drawn in one of three states, per
[`0056`](../../decisions/0056-the-visual-language-encodes-three-states.md), and the tree, the object
listing and the attribute values only ever reach two of them: established, or unknown. A tree node
does not grade the container it names, and an attribute value does not grade the value it shows.

The judging is the only thing in this product that says something is wrong, and it says it as a
finding. A column an administrator reads as a verdict, filled by anything other than a rule that ran,
is the worst thing this screen could do.

---

## The findings and the evidence fail separately

`Refusal` is about the bundle. `FindingsRefusal` is about the judgement beside it. They are separate
files with separate remedies, and a bundle can be read perfectly with no judgement next to it at all.

Telling an operator his evidence could not be opened, when the truth is that the judgement could not,
sends him to re-capture a forest for nothing.

The same distinction runs one level deeper, in the grid itself:

- **A bundle nobody judged is refused, not shown as a clean forest.** An empty list means nothing on
  its own, so the judgement layer hands findings out beside the rules that ran.
- **A judging that ran and matched nothing says so**, which is a different fact and a good one.
- **An empty *filtered* grid says nothing matched the filters.** Empty with no filter is about the
  directory; empty with a filter is about the question. Stating the first while the second is true
  would tell an operator his container is clean when he has narrowed to a severity that happens to be
  absent.

---

## The findings are scoped by the same selection as the objects

The container selected in the tree scopes both lists. An operator who selected `OU=People` and
switched to findings is still asking about that container, and a grid that widened to the forest
would answer a question he did not ask.

That state is held once, on the screen, rather than once per list — two selections that can disagree
is a defect waiting for the day they do.

---

## The grid pages forward, and remembers where it has been

Findings are read a page at a time by `JudgementReader.ReadPage`, which is described in
[`the judgement store`](../judgement/the-judgement-store.md). What that costs this screen is that
**paging only goes forward**: a page knows where it ended, not where the one before it began, so
stepping back means keeping a stack of the marks already shown. The alternative is an offset, which
is the expense the paging exists to avoid.

**Changing a filter empties that stack.** A different filter is a different list, and a mark taken
from the old one points into rows the new one may not contain — so the grid would open part way down
a list that no longer exists, with no way back to the top.

---

## What the filters offer is read, never listed

The severities and rules a filter shows are the ones some finding on this run actually has. A list
written into the screen would offer Critical whether or not anything is critical, and an operator who
picks it and gets an empty grid has learned only to distrust the control.

They are read once for the run rather than per selection: they describe the whole judgement, and
scoping them to the selection would make a chosen filter vanish from its own list on the next click.

---

## Opening an object replaces the grid, and the tree stays

The predecessor used a left pane and a pop-out window, both because two panes left no room for an
entry table on a laptop. Here the object takes the grid's place — but the tree remains, because an
operator reading one object's permissions is still somewhere in the directory and will move to a
neighbour next.

**Double-clicking a finding opens the object it is about, on its findings section.** The finding
names a distinguished name; the screen opens that object the same way the listing would, so there is
one path to an object and not two.

**Closing an object leaves the findings alone.** The grid is not reloaded on return, so the operator
comes back to the page he left rather than to page one — which after a long scroll is the difference
between navigation and punishment.

---

## Which sections an object has is decided by its class

`ObjectSectionCatalog` maps a class of object to the sections it has, and the list is driven by the
class and never by whether a value happened to arrive. An object whose account attributes all failed
to read still has an Account section — saying the values are missing — because a section that
disappears when its contents fail is a screen quietly reporting *nothing to see*.

A section that is named but not yet built says so, rather than rendering empty. And a section a class
does not have leaves the operator's selection alone rather than resetting it, so moving between two
objects of different classes does not throw away where he was reading.

`ObjectSectionCatalogTests` holds every attribute a class justifies to a section that claims it, so
curation cannot hide a value the capture actually collected.

---

## A selected finding says what it means and what to do about it

Below the findings grid sits a panel carrying two blocks for the selected row: **why it matters** and
**what to do**, with the Microsoft page the reasoning rests on when one is recorded. They come from
`RuleGuidanceCatalogue`, looked up by rule identifier, and are described in
[`what a finding is`](../judgement/what-a-finding-is.md).

**A grid that says what is wrong and leaves the operator to work out what to do is half a product.**
The owner's decision of 2026-09-01: this is a working surface administrators clean up from, not a
preview of a report.

**It binds to a `SelectedFinding` property, not to the collection's current item.** The current-item
path reads as a property name to `ViewBindingGateTests`, so a binding through it is one no gate can
resolve — and a view naming something no view model publishes is how this shell crashed once with the
build green, which is why `ViewResourceGateTests` exists. The same shape is already used by the run
library and the object sections.

**A rule with no guidance says so.** A stored judgement outlives the build that made it, so a bundle
can carry a finding from a rule this build no longer runs. The panel then states that no guidance is
recorded rather than showing an empty box, because blank space where an explanation belongs reads as
*there is nothing to say about this* — a different claim, and the wrong one, per
[`0002`](../../decisions/).

**What it must never say is that the finding is now resolved.** That is a claim about every route to
the object, which the judgement half must prove rather than assert. The wording is held by
`RuleGuidanceTests`, which fails the build on copy that goes further.

---

## Membership evidence stays with one finding

**Membership detail under `0108` is built on both finding surfaces.** The selected finding panel and
an object's Findings section each have a **View membership evidence** expander. It shows one block
per initial membership, with the reached roots, captured names, scoped identifiers and supporting
chains beneath it. Primary links, distribution paths, unknown group types and direct catalogue
protection are stated explicitly. This adds detail, not finding rows. Partial summaries name their
limits, say the displayed count is not a total, and prevent the finding row from showing complete
coverage. The text does not promise a minimum set of removals or elimination of other privilege.

`MembershipEvidencePresentationTests` exercises the wording; `ViewBindingGateTests` checks the
exact bindings in both real templates. Disconnecting the findings detail binding and, separately,
the object completeness binding was observed failing with the missing property named.

## The rules tab says what was checked, which no findings grid can

The fourth tab under Assets lists **every rule this build ships**, each with what it looks for and
what it did to the run being read. It is the only place in the product where the description of a
check is reachable without a finding to hang it on, and that is what closes `P-118`: the same words
sat under the findings grid, so on a forest with nothing wrong with it they were on no screen at all.

**The catalogue is the list and the judgement only annotates it.** `AssetsViewModel.ListRules` walks
`RuleCatalogue.All` and looks each rule up in what `ReadRuleExecutions` returned. Built the other way
round, a rule the judging never scheduled would be absent — and a rule missing from a list of rules
reads as a rule that does not exist. An execution naming a rule this build no longer ships is
appended afterwards rather than dropped, because a judgement outlives the build that wrote it and
dropping the row would quietly shrink the account of what was done to the bundle.

**Four different things draw an empty findings grid, and this tab is where they are told apart.** A
rule that judged every object it was about and reported nothing; one that could not read what it
declared; one that failed; one that was never scheduled. `RuleRowViewModel.Outcome` states which in
a sentence — *judged 2,082 objects and reported nothing* is a coverage claim, and the indeterminate
wording names the attribute that was missing and says the result is a floor rather than a total.
`RuleRowViewModel.State` marks a rule that found something as established-bad rather than a fault:
the rule did its job and the forest is what is wrong. `FactState.Fault` is kept for the rule itself
failing, which is a defect in the product.

**It is not scoped by the tree, and the screen says so.** A rule is a question asked of the whole
forest, so `ListRules` runs when the tab is chosen and when the run is read again, and not on any
selection or level change. Narrowing it would put *judged 2,082 objects* beside a container the
judging never counted separately.

**A judgement that will not open is a sentence, not a silent list of rules that did not run.** Those
are opposite facts calling for different actions, and the second wording would state that nobody
judged the bundle while the truth is that its judgement is unreadable.

---

## What this page does not decide

The three-state visual language, what the product calls a finding, and whether an accepted finding
stays visible are all decided in
[`how results are shown`](../../areas/how-results-are-shown.md) and the records it names. Where this
page and a record disagree, the record wins and the disagreement is a defect.
