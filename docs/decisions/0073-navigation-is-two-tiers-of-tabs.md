# 0073 - Navigation is two tiers of tabs, and an unbuilt tab says so

Date: 2026-08-18
Status: Accepted

Supersedes the **No screen is stubbed** clause of
[`0045`](0045-the-shell-is-built-before-the-judgement-half.md). The rest of `0045` stands.

## Context

`0045` decided the shell is built before the judgement half, and that no screen is stubbed: the
dashboard, reports and offline directory tree were left out entirely rather than built as empty
scaffolding, on the grounds that *a screen that appears to report and reports nothing is the
failure this repository already guards against, and it is worse on a screen than in a test,
because a screen is what a customer believes*.

That held while the navigation was a side rail carrying two entries. It stopped holding when the
owner asked for **two tiers of tabs** - a first row for where you are in the product, a second for
which view of that thing you are looking at. The shape of a navigation cannot be judged from the
two entries that happen to be built, and the owner is the only person who can judge it. The same
reviewability argument that `0045` itself rests on therefore now points the other way.

The predecessor asked the second question in exactly this place: its Assets screen carried
*Findings, Escalation Paths, Groups, LAPS Status, Objects* across the top, all scoped by the
container selected in the tree.

## Decision

**Navigation is two rows of tabs at the top of the window, and the side rail is removed.** The
first row is Home, Dashboard, Assets, Runs and Settings. The second row appears only for a section
offering more than one view, so a section with one view carries no second row rather than a single
tab that switches to where the operator already is.

**A tab may exist before the thing behind it does.** This is the clause of `0045` that is
overruled, on the owner's instruction of 2026-08-18.

**What stands behind an unbuilt tab names what is missing and states that it reports nothing about
the directory.** This is the part of `0045`'s reasoning that survives intact, and it is the whole
of the safeguard:

- It never renders an empty result. No empty findings table, no count of zero, no grid with no
  rows.
- It says *not built yet*, names what is absent, and says outright that it states nothing about the
  customer's forest.

An empty findings list is read by an administrator as *my directory is clean*, not as *nothing has
looked*. That reading is the failure `0002` exists to prevent, and no change to sequencing makes it
acceptable.

**The two rows are drawn differently, deliberately.** The first is the product's own navigation and
keeps the navy the rail wore; the second sits on the page beneath it, marked by an underline rather
than a fill. The risk of two rows is an operator who cannot tell which row he is switching, and the
answer is that they do not look alike.

## Consequences

**The window gains about 190 pixels of width**, which goes to the object list - the widest thing in
the product.

**A tab that lies is now one careless edit away.** The guard is a test asserting that what stands
behind an unbuilt tab says it reports nothing about the directory, rather than the tab's mere
absence. `ShellViewModelTests.AFindingsTabWithNoFindingsEngineSaysNothingHasLooked` and
`ShellViewModelTests.ASectionThatIsNotBuiltSaysItReportsNothingAboutTheDirectory` are that guard.

**The rail's own record is reversed.** `docs/areas/how-the-app-looks.md` recorded the rail as navy,
product name at the top, Home and Runs and nothing else. It has not been reviewed on a running
window in this form, and the tabs have not either.
