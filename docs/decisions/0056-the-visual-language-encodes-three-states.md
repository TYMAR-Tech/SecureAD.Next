# 0056 - The visual language encodes three states, and colour is never alone

Date: 2026-08-16
Status: Accepted

Discharges the deferral in [0046](0046-the-shell-is-wpf.md), which chose WPF knowing the product
would look plain until this record existed and said so: *"The visual language is unbuilt work, and
this record is where that debt is acknowledged."*

## Context

Every fact this product puts on screen has three states, not two. A domain controller's PDC emulator
role is held, not held, or **not established**. A password settings container is readable,
unreadable, or **never asked about**. A machine's site is known, known to differ, or **not
computable because the forest declares no subnets**.

Fourteen months of decisions exist to keep that middle state distinct, and until now they have done
it in sentences — `Established`, `PreflightAnswer`, `PdcEmulatorKnowledge`, each with a distinct
wording for the middle case. [`0002`](0002-absent-view-means-degraded-run.md) is the record they
descend from.

**A visual language is where that distinction is most easily lost.** The ordinary way to style a
status is two colours: green and red, tick and cross. Applying a two-state treatment to a
three-state fact deletes the middle state silently, in the one layer a customer actually looks at.
An operator would then see a fact the run never measured rendered identically to one the run
measured and found wanting — and would make a security decision on it.

The old application's three preceding defects (`F-S40-8`, `F-S40-10`, `F-S40-11`) were each one
instance of this: an unasked question rendered as a negative answer. They were caught in wording.
Nothing yet catches them in appearance.

## Decision

**1. Three states get three treatments.** Established-and-good, established-and-bad, and
not-established are visually distinct from one another. A fourth treatment exists for a fault the
run itself reported. A control that offers two status treatments may not be bound to a three-state
fact.

**2. Colour is never the only difference between two meanings.** Every state carries a second
carrier — shape, weight, an outline, a prefix, a glyph drawn in XAML. An operator who cannot
distinguish red from green must be able to tell a fault from an unknown from a clean answer. This is
not an accessibility nicety in a tool people make security decisions on; it is the same requirement
as the three-state rule, restated for a reader the palette does not serve.

**3. Not-established is quiet by default, and quiet is a default rather than a law.** A single
unestablished fact is neutral and plainly marked: it is not a failure, and styling every one as a
failure would train an operator to dismiss the treatment within a week — at which point it hides
genuine problems rather than surfacing them.

**But a gap that carries risk may be raised, and which gaps those are is decided per screen by the
owner.** It depends on the screen and on the information: an unknown that merely reflects how a
forest is configured is not the same as an unknown that leaves a real exposure unmeasured. This
record fixes the default and the vocabulary, not the individual judgement. Each surface records its
own answer in [`how-the-app-looks.md`](../areas/how-the-app-looks.md) as it is built, and is
reviewed by the owner against a running window.

**4. A run may not appear clean while carrying unknowns.** Independent of how any single fact is
styled, the total is stated once on any surface that shows unestablished facts. Quiet rows, honest
total.

**There are two such totals and they are not interchangeable.** Before a run, the question is *how
much of what I am about to audit could not be established* — composed from `PreflightReport`,
together with facts held outside it such as the operator's site. After a run, the question is *how
much of what I audited did I fail to read* — that is `RunCoverage`, which already answers it. A
surface states the total belonging to its moment, and neither is derived from the other.

**5. Red is reserved for critical findings.** The capture-side screens do not spend it. A preflight
prompt, an unestablished fact and an operator choice all have treatments that are not red, so that
when the judgement half of the product arrives the colour still carries its meaning. A palette that
has already spent its strongest signal on gaps has nothing left for the thing an auditor came for.
This reserves a severity ramp in the palette that no screen built before findings may consume.

**6. Every colour is named for what it means and lives in one place.** A brush is
`NotEstablishedForeground`, never `Orange`. Names survive a palette change; literals do not. A
colour literal in a view is a build failure.

**7. The palette is built to be swapped, and only one is shipped.** Every colour resolves through a
single dictionary of values, so a second theme is later a matter of supplying values rather than
revisiting screens. Only the light palette ships. This is structure for a future theme, not a second
theme: a design system built to switch before it has been built to work once is two unfinished
designs.

**8. Density is set per surface, not globally.** Tables and grids are dense — this is a tool an
administrator reads for hours, and vertical space spent on padding is a row he has to scroll for.
Wizards and settings are comfortable. Both resolve through named spacing steps, so the balance can
be retuned centrally when it has been used against a real forest.

## Consequences

**A two-colour status control cannot be used, and there is no shortcut.** Standard treatments
assume two states. Each status surface is built here, once, and reused.

**Whether a given gap is raised is settled per screen, and that recurs for the life of the
project.** This is accepted rather than regretted: the judgement depends on what the screen is for
and what the gap costs an auditor, and no rule written in advance can make it. What this record
fixes is the vocabulary and the default, so each conversation is about one screen rather than about
first principles. The mechanism that makes it affordable is that the shape is agreed before the code
and the correction afterwards is cosmetic.

**The palette carries a severity ramp that nothing may use yet.** Decision 5 reserves red for
critical findings, which do not exist. Building the ramp now and leaving it unspent is deliberate —
the alternative is discovering, at thirty screens, that the strongest signal in the product has
already been spent on prompts.

**The gate is on colour literals, not on the rule.** A build failure catches `DarkOrange` appearing
in a view. It cannot catch a three-state fact bound to a two-state control, nor a screen that raised
a gap it should have left quiet — those need review against a running window, and they are named
here so a reviewer knows to look for them.

**The pre-capture total does not exist and must be built.** Decision 4 requires it.
`PreflightReport` carries the parts — `ChosenWithoutFullKnowledge`, `CouldNotReadPasswordSettings`,
`ReadFromPdcEmulator`, `Blocking` — as separate per-category lists, with no sum, and the operator's
site is held outside it entirely. Composing the total is work this record creates rather than work
it assumes. `RunCoverage` supplies the post-capture total already.

**Dark mode is cheap later and is not free now.** Naming every colour semantically and routing it
through one dictionary costs discipline on every brush added. That cost is accepted deliberately.

**Nothing about what is said changes.** This record governs appearance only. A sentence on screen
that is wrong is a finding with a severity, and a sentence that is merely ugly is also a finding —
neither is edited in passing while styling.
