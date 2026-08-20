# S-6 — Gate 4, an answer that says whether it was reached

**Type:** slice
**Reviewed at commit:** `HEAD` of `master` at the time of writing
**Size:** 2 new test files, 1 new document, 2 edited documents
**Date:** 2026-08-10

## What it does

Gate 4 makes it a build failure for a public member to hand back an answer that cannot say whether
it was reached. A method that returns a bare number gives the caller no way to tell *"I looked, and
there is nothing"* from *"I could not compute this"*. Both are zero. Both print as an empty grid or
a count of nought. `UnvouchedResultGateTests` fails the build when a member whose name claims a
count returns a plain number, and when a collection comes back from a type that says nothing about
whether it managed to look.

A customer never sees this gate. What he would have seen without it is on record. The old product's
exported forest report opens with an executive summary of counts, and four of those counts were
read by members ending `catch (SqliteException) { return 0; }`. On a run whose analysis had not
finished, the summary printed three precise zeros directly beneath a banner warning that sections
might be missing. A reader weighing a vague warning against precise numbers believes the numbers —
and a report is the artefact most likely to be forwarded to somebody who never saw the banner at
all.

This is the one failure an audit tool cannot have. A screen reporting *"no dangerous permissions
found"* when the truth was *"this check never ran"* is worse than a screen that reports nothing,
because the customer acts on it and has no way to tell the difference.

## Shape

- `next/tests/SecureAD.Next.Tests/Architecture/UnvouchedResultGateTests.cs` — the gate: two fires,
  a scanner self-test, a historical-defect theory, three predicate theories and both halves of the
  exemption-decay test. Thirty-four cases.
- `next/tests/SecureAD.Next.Tests/Documentation/UnvouchedResultDocumentationTests.cs` — binds this
  document to the gate and to the README's gates table, per README §When a document counts as
  documentation.

No production code changed. Gate 4 adds no types to the rebuild, and that is a finding in itself:
the kernel already answers gate 4 in three places, so there was nothing to build.

## Dependencies

- **Depends on:** the compiled `SecureAD.Kernel` assembly, which it reflects over; `Result<T>`,
  which is the escape it offers; `OldAppInventory.RepositoryRoot()` in the documentation test.
- **Depended on by:** every future session that adds a public member returning a number or a list.
- **Layering violations:** none. The gate lives entirely in the test project.

## The decisions, and what each costs

#### Reflection, not a text scan

**Chosen:** reflection over the compiled production assembly.

The question gate 4 asks is *what does this member return*, and a return type is a fact the compiler
holds. A text scan cannot resolve `var`. It cannot tell a return type from a parameter of the same
type on the line above. Most importantly it cannot tell a public member from a private one, and this
gate is stated for the public surface — the boundary across which the ambiguity actually travels to
a caller who cannot see the implementation.

The precedent in this repository runs both ways and each direction was chosen for a stated reason.
`ConceptRegistryTests` reflects, because a declaration is a fact the compiler holds.
`NullDefaultGateTests` deliberately scans text, because its subject is a syntax form — `= null` —
that reflection erases, and because a text scan cannot tell a constructor from a method. Gate 4's
subject is a type, so it reflects.

**What it costs:** two things, both real and both shared with gate 2.

- It sees only what compiles. A member in a file excluded from the build is invisible — which is
  what the seventh guard, the orphan-file check in `GreenfieldGateTests`, exists to make impossible.
- It sees only .NET. A count computed in SQL and rendered straight into a report never passes
  through a member the gate can inspect. That is F-S6-3 below.

#### What a bare count is, precisely enough to test

This is where the gate lives or dies, and it is the trap this session was most likely to fall into.

**Chosen:** a member whose **name** claims a count, returning a number that carries nothing beside
it.

The reason the name has to do the work is that an `int` carries no units.
`GenericRightsExpander.Expand` returns an `int` that is a Windows access mask.
`CanonicalAceComparer.Compare` returns an `int` that is an ordering. `SchemaGuidCatalog.Version` and
`AceCanonicalization.Version` return an `int` that is a format number, and
`ParsedSecurityDescriptor.ControlFlags` returns a `ushort` that is a bit field. Forbidding any of
these would be nonsense. A rule that fired on every `int` in the tree would be switched off within
a week, and a rule narrowed until it fired on nothing was never a gate.

So the shapes are anchored globs — `Count`, `*Count`, `*Counts`, `NumberOf*`, `Total*`, `*Tally` —
matched against the whole name, never as a substring, so `Discount` is not a count. The same rule
and the same reason as the concept registry's member shapes.

**Tested against the members the old code actually declared.** `GridSummaryQueryService` declared
`GetUnusualOwnerCount`, `GetDangerousAceCount`, `GetDangerousAceGridCount` and
`GetSuppressedFindingCount`, all `public int`, all ending `catch (SqliteException) { return 0; }`
(`git grep -n "catch (SqliteException) { return 0; }" -- src`, four sites). It also declared
`QueryControlTypeCounts` and `QuerySourcePrincipalCounts`, which return lists of counts and are the
collection form of the same defect. All six are asserted in
`TheGateWouldHaveCaughtTheDefectsThatMotivatedIt`, so a shape narrowed until it would no longer have
caught the members decision 0004 was written about fails the build. That is the evidence for the
claim that this gate works, and it is why the test exists rather than a comment saying so.

**A nullable integer is still a bare count**, and that is a deliberate re-derivation rather than an
oversight. `int?` is better than `int` — it can at least say *nothing here*. But
`docs/decisions/0004-unknown-counts-name-the-failed-phase.md` requires an unvouchable count to
render as unknown **naming the phase responsible**, and a bare `null` names nothing. The old
product's `ExecuteCountQuery` returned `int?` and is the nearest that code came to getting this
right; a reader still could not tell which phase had failed. The assertion is taken from the
decision record rather than from the shape of the old code.

**What it costs:** a count under a genuinely new name gets through. A method called
`DangerousAces()` returning `int` is invisible here, exactly as a duplicate under a new name is
invisible to gate 2. That is the price of the only line that does not fire on an access mask, and it
is paid down by review rather than by the build.

#### What a bare collection is, and why an empty list is not always a defect

**Chosen:** a collection is bare when the type handing it back says nothing about whether it
managed to look.

`docs/decisions/0002-absent-view-means-degraded-run.md` states the test in so many words: *"before
adding any guard that returns a default for an absent or empty result, state what the reader should
conclude from it — and if 'nothing' could mean either a fact about the domain or a failure of the
query, the guard must distinguish them."* So the gate is not "no method returns a list". It is "no
method returns a list from something that cannot fail out loud".

A **vouched type** is one declaring a member that states its own completeness: `Errors`,
`Warnings`, `Verdict`, `IsComplete`, `FailedPhase`. The shapes are these because the rebuild
already answers gate 4 that way in three places, and the gate was written to recognise the pattern
that exists rather than to impose a new one:

- `ParsedSecurityDescriptor` carries `Errors` beside `DaclAces`, so an empty ACE list beside a
  populated `Errors` is visibly not an empty DACL.
- `AceNormalizationResult` does the same for the canonical ACEs.
- `PermissionAssessment` carries a `Verdict` whose fourth value is `CannotClassify`, so "not
  assessed" cannot be read as "safe". Its own remarks already cite decisions 0002 and 0004.

There is a fourth, and it is the neatest instance of gate 4 in the product: `DaclState` distinguishes
`Null` from `Empty`. A null DACL grants everyone everything; an empty DACL grants nobody anything.
Rendering both as "no entries" would be the same defect wearing different clothes.

**Members of a vouched type are excluded**, because the container already carries the statement. A
gate that policed `AceNormalizationResult.Aces` as well as `AceNormalizationResult` would fire on
the rebuild's own correct code on its first run, and a gate that is wrong on day one gets switched
off. This repository has made that mistake before.

**What it costs:** the vouch is structural, not semantic. A type declaring an `Errors` property it
never populates passes. The gate checks that the channel exists; whether anybody writes to it is a
reader's job, and F-S6-2 records it.

#### Whether `bool` belongs in scope

**Chosen:** no, deliberately, and recorded rather than pretended away.

`false` carries the same ambiguity as `0` in principle. In practice no name shape separates *"the
predicate ran and said no"* from *"the predicate did not run"* — both are `Is*` and `Has*`. A rule
over `bool` would fire on `Result<T>.IsSuccess`, on `GenericRightsExpander.HasGenericRights` and on
`ParsedSecurityDescriptor.IsDaclProtected`, every one of them a total predicate over a value already
in hand, and the gate would be switched off.

The place the ambiguity actually bites is a *finding*, and findings arrive as collections and counts
rather than as booleans — which is why the two fires are where they are. The right answer for a
fallible predicate is the one `PermissionAssessment` already demonstrates: a four-valued verdict
including `CannotClassify`, not a `bool`. That pattern is established here by example rather than by
the build, and the gap is F-S6-1.

The same reasoning excludes a nullable single value: `SchemaGuidCatalog.GuidFor` returns `string?`
and `DnHelper.GetParentDn` returns `string?`, and both are total functions where `null` means one
thing only. Bringing them in would need a second and a third exemption on a seventeen-type surface,
which is how a rule becomes an allowlist.

#### The one exemption, and what makes it expire

**Chosen:** `SchemaGuidCatalog` is exempt from the collection half, and nothing else was.

Run without the exemption, the collection check fires on exactly two members —
`SchemaGuidCatalog.Entries` and `SchemaGuidCatalog.FindByGuid` — and on nothing else in the five
finished rows. Neither is a defect. The catalogue is a table compiled into the assembly. It reads
nothing, opens nothing and cannot fail, so an empty answer from `FindByGuid` means one thing only:
the GUID is not in the table, which the member's own summary already says is an ordinary answer
because a forest carries schema extensions this table cannot have heard of.

**Amended 2026-08-11 by ledger row B2, and it is now two.** `CapturedAttributeCatalog` — the list of
attributes capture asks a domain controller for — is the same kind of thing for the same reason: a
table compiled into the assembly, reading nothing and unable to fail, whose `AttributesFor` cannot
even return an empty answer because the universal attribute set is always included. Widening an
allowlist is how a gate dies, so this is recorded rather than done quietly: it is the second entry
and not the tenth, the reason is identical rather than merely similar, and both decay tests below
cover every entry rather than the first. A third entry whose reason is not *a compiled table that
cannot fail* does not belong there. Recorded as F-S7-25 in
[`S-7`](S-7-capture-dispositions.md).

Gate 2 needed no exemption and says so. This one does, so it carries the decay test that
`SchemaGuidSingleSourceGateTests` established, in two halves:

- `TheCatalogueExemptionsAreStillEarningTheirPlace` — if either catalogue stops returning a
  collection, that exemption is dead and goes with it.
- `TheCatalogueExemptionsHaveNotComeDue` — the exemptions rest on the claim that a catalogue cannot
  fail, and this fails the build the moment that stops being true for either of them: any member
  returning `Result<T>`, or any member named `Load*`, `Read*`, `From*`, `Fetch*`, `Refresh*` or
  `Open*`.

That trigger is not hypothetical.
`docs/decisions/0014-capture-reads-the-schema-partition.md` says capture reads the schema partition,
so a catalogue that can be loaded from a live forest is coming. On that day an empty catalogue will
mean either an empty answer or an unread partition, and the exemption will fail rather than quietly
becoming permanent.

**What it costs:** the exemption is keyed on a type name, so renaming `SchemaGuidCatalog` silently
widens the gate rather than narrowing it — the safe direction to be wrong in, since the rename would
then make the collection check fire and the failure would be loud.

## Verified-safe

- **Nothing the gate forbids already exists in the five finished rows.** K13, K14, K15, K16 and K17
  were run against both fires with the exemption removed. The count fire reports nothing at all. The
  collection fire reports only the two catalogue members described above, and those are a total
  lookup rather than a defect. The judgement the owner was warned he might have to make — whether to
  reopen a finished row — does not arise.
- **The gate does not fire on a number that is not a count.** Checked deliberately against
  `GenericRightsExpander.Expand`, which returns a Windows access mask, and driven as a mutation:
  the same `int` renamed from `EntryCount` to `EntryMask` goes green.
- **`Result<T>` is a working exit, not a theoretical one.** A member that fires as
  `IReadOnlyList<string>` passes as `Result<IReadOnlyList<string>>`, observed as mutation 6 below.
- **The kernel already vouches where it matters.** `ParsedSecurityDescriptor.Errors`,
  `AceNormalizationResult.Errors`, `PermissionVerdict.CannotClassify` and the `DaclState.Null` /
  `DaclState.Empty` distinction, evidence at `next/src/SecureAD.Kernel/Security/`.

## Mutation testing

Ten directions were driven across eight edits. Each edit was confirmed present in the file — by
`git diff --numstat` or by `Select-String` against the edited line — before its result was believed.
That check is habit rather than luck now: a mutation that silently failed to apply produced a false
pass in the K16 session and again in the gate 2 session.

| # | Mutation | Expected | Observed |
|---|---|---|---|
| 1 | `public int EntryCount` added to `SchemaGuidCatalog` | The count fire fires | Fired, naming the type, the member and the return type |
| 2 | The same member changed to `public int?` | Still fires, per decision 0004 | Fired, reporting `Nullable` |
| 3 | The same member renamed `EntryMask`, still `int?` | Nothing; a mask is not a count | Passed, correctly. Recorded so the green is not read as a failure to fire |
| 4 | `LoadFromPartition` added to `SchemaGuidCatalog` | The exemption comes due | `TheCatalogueExemptionsHaveNotComeDue` fired |
| 5 | The exemption replaced with a name matching nothing | The collection fire fires on the catalogue | Fired on exactly `Entries` and `FindByGuid`, and on nothing else |
| 6 | `IReadOnlyList<string> FindDangerousRights()` added to `DangerousPermissionClassifier` | The collection fire fires | Fired |
| 7 | The same member changed to `Result<IReadOnlyList<string>>` | Nothing; that is the escape the gate offers | Passed, correctly |
| 8 | `PublicTypes()` narrowed to a type name that does not exist | The scanner self-test fires | `TheGateReadsTheRealPublicSurface` fired, and `TheCatalogueExemptionsAreStillEarningTheirPlace` fired with it |
| 9 | `*Count` removed from the count shapes | The historical-defect theory fires | Fired on all four old `Get*Count` members and on `FindingCount` |
| 10 | `*` added to the vouch shapes, so everything is vouched | The discrimination theory fires | Fired on `SchemaGuidCatalog` and `CanonicalAce` |

Directions 9 and 10 are the two that matter most, because they are the ways this gate could be
turned into a check that passes while measuring nothing. Narrowing the count shapes makes the first
fire unreachable; widening the vouch shapes makes the second fire unreachable. Both now fail the
build.

## Findings

### F-S6-1 — A boolean that could not be computed is out of scope

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `UnvouchedResultGateTests.IsBareNumber`, which excludes `TypeCode.Boolean`;
  asserted as a case in `ABareNumberIsOneThatCarriesNoOutcomeWithIt`
- **What happens to a user:** the same defect the gate exists for, arriving as `false` rather than
  as `0`. A method answering *"is this principal privileged"* that returns `false` because the group
  expansion did not run reads as *"this principal is not privileged"*, and a customer leaves a
  delegation in place.
- **Why it is this way:** deliberate. `Is*` and `Has*` name both a predicate that ran and said no
  and a predicate that did not run, so there is no shape to fire on. A rule over every `bool` would
  fire on `Result<T>.IsSuccess` and `GenericRightsExpander.HasGenericRights`, which are total
  predicates over a value already in hand, and would be switched off.
- **Options:** leave it, and rely on `PermissionAssessment` as the worked example of the right
  answer — a verdict with a `CannotClassify` value rather than a `bool` (chosen); or require every
  public `bool` on a fallible type to be a three-valued enum, which cannot be expressed until there
  is a mechanical notion of a fallible type, which needs the first component that does I/O.
- **Test cover:** none for the gap. The exclusion itself is asserted, so a later session cannot
  remove it by accident without the theory turning red.
- **Status:** OPEN, accepted by design. Checked 2026-08-10

### F-S6-2 — The vouch is structural, not semantic

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `UnvouchedResultGateTests.IsVouched`, which asks only whether a member of a
  vouching name exists
- **What happens to a user:** a type declares `Errors`, never populates it, and hands back an empty
  list from a query that threw. The grid is empty, `Errors` is empty, and the screen says the
  forest is clean. The gate reports the surface in perfect order.
- **Why it is this way:** whether a channel is used is a question about control flow, and no
  reflection over signatures can answer it. The gate makes the channel compulsory, which is the part
  that can be enforced.
- **Options:** leave it and rely on review (chosen); or add a rule that any `catch` in production
  code must write to an errors channel, which is a text scan over control flow and would fire on
  every guard clause.
- **Test cover:** none, and none is possible at this level. The behaviour is covered where it
  matters by the component's own tests — `SecurityDescriptorParserTests` asserts that a truncated
  descriptor populates `Errors` rather than returning an empty ACE list.
- **Status:** OPEN, accepted for now. Checked 2026-08-10

### F-S6-3 — A count computed outside .NET is invisible to the gate

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `UnvouchedResultGateTests.ProductionAssemblies()`, which reflects over
  `typeof(Result<int>).Assembly`
- **What happens to a user:** the same false zero, arriving by a route the gate does not watch. This
  is the exact route the original defect took: the four offending members were thin wrappers over
  SQL, and the number a reader saw was produced by a query, not by a C# expression.
- **Why it is this way:** the same reason gate 2 has the same limit, recorded there as F-S5-2. A
  text scan wide enough to read SQL cannot tell a declaration from a mention.
- **Options:** leave it and re-examine when the reporting component lands, since the defect is
  reached through a .NET member in every case that matters — the SQL produces the number, but a
  public member hands it to the renderer, and that member is in scope (chosen); or scan the rule and
  report SQL at that point.
- **Test cover:** none, and none is possible until there is SQL to scan.
- **Status:** OPEN, accepted for now. Checked 2026-08-10

### F-S6-4 — A count under a name the shapes do not claim gets through

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `UnvouchedResultGateTests.CountShapes`; a member named `DangerousAces()` returning
  `int` matches none of them
- **What happens to a user:** a false zero the gate did not catch. It is the residual risk of the
  only rule that does not also forbid an access mask.
- **Why it is this way:** an `int` carries no units, so the name is the only evidence available.
  Widening the shapes until nothing escapes means firing on `Expand` and `Compare`, and a gate that
  is wrong on its first run gets switched off — the failure mode recorded in S-5 for the concept
  registry's shapes.
- **Options:** leave it and keep the shapes wider than the members that exist today, so a new count
  has to be named unusually to escape (chosen); or invert the rule to forbid every bare integral
  return with an exemption list, which puts `Expand`, `Compare`, both `Version` constants and
  `ControlFlags` on an allowlist and grows one entry per component.
- **Test cover:** partial. `TheGateWouldHaveCaughtTheDefectsThatMotivatedIt` fails if the shapes are
  ever narrowed below the six historical members; nothing catches a name nobody thought of.
- **Status:** OPEN, accepted by design. Checked 2026-08-10

## Open questions for the owner

None. The one judgement this session was warned it might have to bring back — whether anything the
gate forbids already exists in a finished row, and what it would cost to fix now against leaving it
— does not arise. The gate fires on nothing in the five finished rows, and the two members it would
fire on without its exemption are a lookup in a compiled-in table that cannot fail.

## Not reviewed

**Gate 3** — artefact provenance, `run_id` and `SealedUtc` — is phase 2 and was not touched.

**Gate 5b** remains blocked on a runnable entry point and was not touched.

**Whether a vouched type is filled in correctly.** The gate checks that the channel exists. Whether
a component writes the truth into it is F-S6-2 and belongs to that component's own tests.

**The old product's reporting layer**, where the four false zeros were rendered. Its members were
read by `git grep` for evidence about the shape of the defect. Nothing there is being repaired; the
ledger disposition for those components is not this session's business.
