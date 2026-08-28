# What stage 2a derives

**Code:** `next/src/SecureAD.Derivation/`
**Layer:** Derivation — where a sealed bundle becomes answers about more than one object.

Group nesting, read once out of a sealed bundle and turned into three separate answers. This is the
first phase of the derive stage, and the first thing in this product that answers a question about
more than one object.

**Status: built, 2026-08-27. Wired in 2026-08-28.** Runs end to end over a sealed bundle through
`Stage2aRun.Derive`, which both the window and the command line call once a capture has sealed
evidence. No rule consumes what it produces yet.

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `Stage2aRun` | Deriving a sealed bundle: one pass over the nesting, three closures, one store |
| `DerivationProgress` | How far a derivation has got, for a window that shows it |
| `DerivationRunState` | What became of a derive run as a whole |
| `DerivationPhaseOutcome` | What became of one phase within that run, including one that never ran |
| `ExpansionBudget` | The limits a membership expansion runs under |
| `ExpansionLimit` | Which budget stopped an expansion, when one did |
| `DerivationCompleteness` | What a derivation does not cover, so a partial answer is never read as a whole one |
| `DerivationReader` | Reads a derivation back, and refuses one written to a schema this build does not understand |
| `StoredDerivation` | Everything a derivation recorded: its description, its phases, its size and its completeness |
| `DerivationDescription` | What one derive run recorded about itself |
| `StoredDerivationPhase` | One phase, read back, with why it failed if it did |
| `DerivationSize` | How much the store holds |

<!-- TYPES:END -->

**The derive's workings are internal, deliberately.** The pass, the graph, the SID interner, the
writer, the schema and the three closure derivations are not on this list because nothing outside
the assembly names them — a register row states that anything may come to depend on a type, and
that is the opposite of what is wanted for how this stage happens to do its work. The tests reach
them through `InternalsVisibleTo`, as they do for the command line and the window.

---

## Three products, because one graph answers three questions

An earlier draft of the specification treated group expansion as one closure. That is unsafe, and
the reason is a single arrangement that three different true sentences describe:

```
Alice -> member of -> DistributionGroup-A -> member of -> Domain Admins
```

| Product | What it says about Alice | Built by |
|---|---|---|
| `AuthorizationMembershipClosure` | Not a Domain Admin. No token SID, no access. | `AuthorizationMembershipExpander` |
| `ProtectedPrincipalClosure` | A protected account. SDProp manages her ACL, inheritance is off. | `ProtectedPrincipalDeriver` |
| `LatentPrivilegePaths` | One `groupType` flip from being a Domain Admin. | `LatentPrivilegeDeriver` |

All three come from Microsoft's own guidance and all three are true at once. A single closure would
have to be wrong about two of them.

**The third one is why the arrangement matters.** Nesting a distribution group under a privileged
group grants nothing, so it trips no privilege alert and looks like an untidy mailing list. The
change that arms it is one flag on `groupType`, not a membership edit - and membership edits are
what gets watched. The innocent explanations are commoner: an Exchange-era notification group, a
conversion nobody finished, migration debris. Every one of them leaves the same arrangement behind.

**The second one is not a privilege finding and must not be worded as one.** A protected account has
inheritance disabled, so a delegation applied at its organisational unit silently does not reach it.
`adminCount` stays set after the membership goes away, so this outlives the cause. The sentence is
*your delegation is not doing what you think*, not *this person has privilege*.

## How it is built

```
Stage2aRun.Derive(bundleDirectory)
        |
        v
BundleReader.StreamObjects()
        |
        v
MembershipNestingPass          one pass: interns SIDs, reads nesting, resolves names to SIDs
        |
        v
NestingGraph                   compressed sparse rows over integer ids
        |
        +--> AuthorizationMembershipExpander  --> MembershipClosure
        +--> ProtectedPrincipalDeriver        --> ProtectedPrincipalClosure
        +--> LatentPrivilegeDeriver           --> LatentPrivilegePath[]
                                                       |
                                                       v
                                              DerivationCompleteness
                                                       |
                                                       v
                                              DerivationWriter -> derivation.db
                                                       |
                                                       v
                                              DerivationReader <- read back
```

### Phases fail separately, but they are not independent

Each phase is recorded by name whatever becomes of it, and one that throws does not stop the
others - the facts they derived are still worth writing. The isolation is not uniform, because the
dependencies are real:

| Phase | Needs | Survives |
|---|---|---|
| `MembershipAndNesting` | the bundle | nothing, if it fails |
| `AuthorizationMembership` | the graph | - |
| `ProtectedPrincipals` | the graph only | a failed expansion, degraded |
| `LatentPrivilegePaths` | the graph and the expansion's answer | - |

A phase whose input never arrived is recorded as `DidNotRun`, not `Failed`. They are different
sentences: one has misbehaved and the other has not, and blaming the second sends whoever reads it
looking in the wrong place. A row is written either way, because a store holding no closure because
a phase failed and one holding none because the forest has no nesting are opposite facts.

**A failed phase does not abandon the store.** Abandoning is for a coordinator that could not do its
job. Deriving is the most expensive thing this product does, and discarding three good phases over
one bad one would be paid for again on the next attempt.

`next/src/SecureAD.Derivation/` holds all of it. Facts are written to `derivation.db`, a third file
beside the evidence and the judgement, sealed and renamed the same way.

### Membership is written in names and stored in SIDs

`member` and `memberOf` carry distinguished names. `nesting_edge` carries interned SID ids. The two
cannot be reconciled while reading, because the object a name refers to may not have been streamed
yet - so `DistinguishedNameIndex` interns names on the way past and edges are resolved once the pass
has seen everything. A name no captured object answers to becomes an unresolved trustee rather than
a dropped edge.

### Primary-group membership is real, and is not an edge

`primaryGroupID` names a group the account is a member of, and neither the account's `memberOf` nor
the group's `member` carries the relationship. A traversal reading only those two is incomplete, and
an account whose primary group is a privileged one would go unseen.

It is held as one nullable column on the principal rather than materialised into `nesting_edge`.
Nearly every account's primary group is Domain Users, so edges would add one row per account in the
forest, every one pointing at the largest group there is - and if Domain Users is nested anywhere,
the closure over those edges resolves to the entire directory.

### A SID is unique within its scope, not within the forest

`S-1-5-32-544` is `BUILTIN\Administrators` in *every* domain, and those are different groups holding
different members. Microsoft calls the built-in domain "local in scope". So a built-in SID is
interned under the domain it was captured from, and every other SID by its text alone - a domain SID
already carries the issuing domain inside it, and scoping one would split a single principal into
several.

**Getting this wrong does not lose a fact, it invents one.** Keyed by SID alone, every domain's
local Administrators becomes one principal and their memberships union - so the forest root's
Administrators is reported as containing the child domains' Domain Admins. A cross-domain privilege
path that does not exist is the one finding this product must never produce.

**Being captured twice is not the same as being two principals**, and the cases are separated:

| Seen more than once because | Same principal? | What happens |
|---|---|---|
| a built-in alias exists in every domain | no | one principal per domain |
| a universal well-known SID has a stub in each domain | yes | one principal; the extras are counted |
| a `foreignSecurityPrincipal` stands in for someone from another domain | yes | one principal; the real object's facts win |

The scope is part of the key and never part of the answer: `SidInterner.TextOf` returns the SID the
directory holds, so `ProtectedGroupCatalogue` and every other reader are untouched. Two ids may
return the same text, which is the point.

See [`0087`](../../decisions/0087-a-sid-is-unique-within-its-scope.md).

### SIDHistory is an identity, never an edge

An ACE naming an old SID reaches the migrated principal through it. That is another identity the
principal carries, not another group it is in. Filed as an edge, a closure would walk through it and
report memberships nobody has.

## Where this departs from the predecessor

The old application's `GroupExpansionService` worked and ran against real forests. Read for how it
performed; the differences below are the ones that are load-bearing.

| | Old app | Here |
|---|---|---|
| Expansion | one breadth-first walk per group, from scratch | each component expanded once, bottom-up |
| Cost | groups multiplied by directory size | graph size plus result size |
| Cycles | a visited-set guard, per walk | condensed before anything is walked, and reported |
| SIDs | text, in every closure row | interned to integers |
| Graph in memory | `Dictionary<string, List<string>>` | integer arrays, read sequentially |
| Derived facts | written into `audit.db` beside the evidence | own file, own lifetime |
| Products | one closure | three |
| Primary groups | not tracked | tracked, as a non-edge |

**`GetPrecomputedClosure` in the predecessor has no callers.** Its `visited` set is local to each
walk, so nothing memoised across groups: a subtree beneath three groups was walked three times. The
caching that does exist saves database round-trips, not traversal. That single observation is what
the algorithm here is a response to.

**What it got right and this keeps:** prepared statements reused inside one transaction, a
precomputed set so the inner loop does not query per member, fault isolation per phase, and above
all recording *why* a budget was hit rather than truncating quietly.

## Budgets

`ExpansionBudget.Bulk` is 500,000 closure entries and 30 minutes. The numbers come from the
predecessor's bulk expansion, which is the only place either project has measured anything.

**They do not mean the same thing now.** The old count was node *visits*, and with per-group walks
most of those were ground already covered. Here the budget is over *emitted closure entries* -
the size of the answer rather than the cost of computing it - because that is the quantity that can
genuinely run away.

**There is no depth budget.** The predecessor needed one because a per-group walk following a cycle
does not stop on its own. Cycles are condensed here before anything is walked, so the expansion
terminates by construction and a depth limit could only cut off a legal answer.

### The limit that does not go away

Interning SIDs and expanding each group once reduce what a closure costs to compute. Neither reduces
how large a closure is.

A chain of ten thousand groups, each containing the next, has each group containing everything below
it: fifty million pairs before a row is written. `Stage2a_ADeepChainExhaustsTheEntryBudget` pins
this. The budget is what stands between that and a derivation that never finishes, and the outermost
groups are the ones that go unanswered - so the result is a floor, and says so.

## Two uncertainties, handled opposite ways

A group whose `groupType` was not captured is a group whose type nobody knows. That single
uncertainty is resolved differently in two places, deliberately.

**The membership expansion traverses it.** Refusing would report principals as not holding a
privilege they may hold, and an audit tool that under-reports privilege fails at the thing it exists
for. Traversing can only over-report, which an operator can check. The group is named in
`MembershipClosure.GroupsOfUnknownType` so the doubt travels with the answer.

**The latent-privilege derivation does not report it as convertible.** There is no safe direction
when the claim is about a change: saying *converting this would grant Domain Admins* about a group
that is already security-enabled describes something that cannot happen, and an operator who checks
one and finds it wrong learns to discount the rest.

Same uncertainty, opposite handling, because the sentence being spoken is different.

## What is gated, and what stopped being gated

`AC-64` - **still gated.** Whether the protection process follows primary-group membership is
unevidenced. The citation establishes that the membership is real and that authorization honours it;
nothing says how SDProp traverses it. A principal reaching a protected group only that way is
`Unknown`, never `NotProtected`.

`AC-26` - **no longer gated, decided 2026-08-27.** The specification recorded that no Microsoft
source stated the protection process follows distribution nesting. One does, and it is the same
document already relied on for the adjacent claim. See `docs/MICROSOFT-VERIFICATION.md` for the
citation and the anchor test.

It is recorded as `ProtectedEdgeProvenance.Documented` rather than `Specified`, because it is
product guidance and not an Open Specification. If one is found that contradicts it, that field and
the catalogue version are what change.

## Completeness

`DerivationCompleteness` carries what the specification asks each closure to record, and it is
derived from three independent sources rather than asserted:

| Source | Kind of hole |
|---|---|
| the pass | a member nobody could resolve |
| the pass | a principal captured twice, folded into one |
| the pass | a built-in SID with no domain to scope it by |
| the expansion | a budget reached, and which groups went unexpanded |
| the capture's coverage | a domain not read in full |

`MissingPartitions` keeps whole `DomainCoverage` rows rather than a list of names, so a domain
excluded by choice stays distinguishable from one nobody could reach.

`MembershipClosure.PartialGroups` exists because an empty membership list means two different
things - *reached and found empty* or *never computed* - and without it a rule cannot tell them
apart. A missing input that becomes an empty set reads as a clean result, which is the failure this
whole stage is shaped around.

**`CollapsedStubs` and `UnscopedBuiltins` are counts rather than flags, and only one of them counts
against completeness.** Folding a stub onto the principal it stands in for loses no fact - they are
the same principal - so it is reported and nothing more. A built-in SID with no domain may have
merged two principals that are not the same, which is a fact this graph gets *wrong* rather than one
it omits, so the derivation is not complete while any exist. It should be zero on a whole capture;
it is measured rather than assumed, because a derivation reporting none and one that never looked
are different facts.

### It reaches the store

Completeness is recorded in the derivation alongside the closures, in `derivation_completeness` and
the three tables beside it, and `DerivationReader` hands it back on `StoredDerivation` as a
non-nullable member. A caller cannot read how much the store holds without the coverage of it.

**Every derivation records one, including a whole one.** An absent row would mean both *nothing was
missing* and *nobody recorded whether anything was*, and the second would read as the first. For the
same reason the three lists are written even when empty: an empty table means the derivation had no
holes of that kind, where an absent one would mean nobody looked.

**`IsComplete` is stored rather than worked out from the lists.** A domain the capture never read
leaves no unresolved trustee and no partial group behind - there is nothing in the graph to be short
of - so a reader computing completeness from what it can see would call that store whole.

The two degraded paths say so rather than recording nothing:

| What happened | What is recorded |
|---|---|
| the pass produced nothing | `NothingWasRead` - never complete, and still carrying the capture's coverage, because an empty store is also what a forest with no groups would produce |
| the pass ran, the expansion did not | `WithoutExpansion` - never complete whatever the pass found, because a perfectly read graph with no closure looks whole by every other measure |

## Known gaps

**`dSHeuristics` is captured, and the protected set is the forest's own.** Character 16,
`dwAdminSDExMask`, can remove Account, Server, Print or Backup Operators from the set AdminSDHolder
protects, and the derivation now applies it. Three states are held apart, because collapsing them
is how a hole gets reported as a clean answer:

| What the bundle carries | What the derivation says |
|---|---|
| a value naming excluded groups | those groups are not protected, and `ProtectedCatalogueNarrowedByForest` says why the set is smaller |
| the object, holding no value | the published catalogue applies, and the forest was asked - MS-ADTS makes an absent value a documented answer, not a gap |
| no such object, or a bundle captured before catalogue version 5 | the published catalogue applies, and `ProtectedCatalogueIncomplete` says nobody looked |

**The middle row is what changed.** Before this the derivation stated
`ProtectedCatalogueIncomplete` on every run whatever the evidence, which is doubt a forest that gave
a clear answer does not deserve.

**An excluded group is removed, never deleted.** `IsInThePublishedCatalogue` still answers for
Microsoft's set, so an operator asking why a group is unprotected can tell *never in the catalogue*
from *taken out by this forest* - different facts with different remedies.

**Confirmed against a real forest, 2026-08-28.** `tymar.lab` was given
`dSHeuristics = 000000000100000f` through `next/tools/Set-LabDsHeuristics.ps1` and captured. The
value reached `captured_object` on the Directory Service object, character 16 resolved to all four
bits, and the four operator groups left the protected set while Administrators and Replicator stayed
in it. The same forest read as excluding nothing before the value was set, which is the case every
other forest will present.

**Deriving runs between the capture and the judging.** `NewAuditViewModel` calls it through
`IDerivationLauncher` once a capture has sealed evidence, and `SecureAD.Cli` calls `Stage2aRun.Derive`
directly after it prints the sealed bundle. It goes before the judging because what it produces is
what a rule reading more than one object will rest on, and a judging that ran first would rest on
nothing. A derivation that could not be done is reported and does not stop the judging: every rule
that exists today reads one object and needs nothing derived. See
[the New Audit screen](../shell/the-new-audit-screen.md).

**A bundle can also be derived on its own.** `securead --derive <bundle>` opens a sealed bundle,
derives from it and writes beside it, contacting no controller. It exists because deriving improves
while evidence does not: a bundle captured before this stage understood something can be derived
again without reading the forest a second time, which for a large forest is hours against seconds.
It refuses to be combined with anything that captures - naming a library, a forest or a controller
beside it asks for two things at once, and guessing which was meant is how an operator gets a
capture he did not ask for. A missing derivation is a failure here rather than the tolerated outcome
it is after a capture: a run asked only to derive has produced nothing if it did not.

**Closures are written and not read back.** `DerivationReader` reads the header, the phases and how
much the store holds, which is what the window needed: `DerivingOutcome` now reports the principals
and nesting relationships a derivation produced instead of how far its pass read. It deliberately
offers no way to ask *who is in this group* — nothing consumes a closure yet, and an interface shaped
against no caller is how the predecessor's `GetPrecomputedClosure` came to have none. That part waits
for the rule that needs it.

**A store from another schema is refused rather than read.** Version 2 gave the SID dictionary a
scope; a version 1 store keys principals by SID alone, so every domain's built-in groups are one
principal in it with their memberships merged. Reading one would hand back the fabricated
cross-domain privilege path [`0087`](../../decisions/0087-a-sid-is-unique-within-its-scope.md) was
written to remove. Version 3 added completeness, and a version 2 store records none - reading one
would report a derivation of unknown coverage as a whole one. Either way the refusal names what
differs and says the evidence is untouched.

**No rule reads any of this.** The rule interface over declared derived facts is a judge-stage
change and has not been made. `IRule` still takes one object. The right moment to design its
replacement is when the first rule that needs a derived fact exists to shape it.

## What is built

**The test is the evidence; this table is only the index.**

**Confirmed in lab** is the date the owner saw this working against a real forest. The stage was
first run against one on 2026-08-28, over a three-domain bundle - which is where the scoping defect
[`0087`](../../decisions/0087-a-sid-is-unique-within-its-scope.md) records was found and fixed. The
run exercised the pass, the expansion and both derivations end to end, and every phase succeeded.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| Read a bundle's group nesting once, without a second pass per question | `MembershipNestingPassTests` | |
| Have primary-group membership counted, though it is in neither `member` nor `memberOf` | `MembershipNestingPassTests` | |
| Have a member from an uncovered domain recorded as a gap rather than dropped | `MembershipNestingPassTests` | |
| Have `sIDHistory` treated as another identity rather than another membership | `MembershipNestingPassTests` | |
| Hold a forest's nesting in memory as integers rather than SID text | `NestingGraphTests` | |
| Keep primary-group membership separable from ordinary nesting, so a gated edge stays gated | `NestingGraphTests` | |
| Expand every group once rather than once per group above it | `AuthorizationMembershipExpanderTests` | |
| Have a membership cycle terminate and be reported rather than merely survived | `AuthorizationMembershipExpanderTests` | |
| Be told a distribution hop carries no authorization | `AuthorizationMembershipExpanderTests` | |
| Be told when a closure hit its budget instead of being handed a short answer | `AuthorizationMembershipExpanderTests` | |
| See which principals AdminSDHolder covers | `ProtectedPrincipalDeriverTests` | |
| See `Unknown` rather than `NotProtected` where the traversal is unevidenced | `ProtectedPrincipalDeriverTests` | |
| Have one gated edge not turn the whole forest into a shrug | `ProtectedPrincipalDeriverTests` | |
| Have the protected set match what Microsoft publishes | `ProtectedGroupCatalogueMicrosoftAnchorTests` | |
| See which distribution groups are one conversion from conferring privilege | `LatentPrivilegeDeriverTests` | |
| Not be shown a latent path that would change nothing for anybody | `LatentPrivilegeDeriverTests` | |
| Read a derived answer beside what it does not cover | `DerivationCompletenessTests` | |
| Tell a domain left out by choice from one nobody could reach | `DerivationCompletenessTests` | |
| Have derived facts sealed and named only once every phase has finished | `DerivationWritingTests` | |
| Derive a whole bundle in one call | `Stage2aRunTests` | |
| Be refused rather than half-derived when a bundle cannot name its capture | `Stage2aRunTests` | |
| Keep three phases' facts when a fourth throws | `Stage2aRunTests` | |
| Tell a phase that failed from one that never ran | `Stage2aRunTests` | |
| Keep each domain's built-in groups apart, with their own members | `MembershipNestingPassTests.EachDomainsBuiltinGroupIsAPrincipalOfItsOwn` | 2026-08-28 |
| Read one SID captured in several places as one principal | `MembershipNestingPassTests.OneSidCapturedInSeveralPlacesIsOnePrincipal` | 2026-08-28 |
| Keep a real object's facts rather than a stub's | `MembershipNestingPassTests.ARealObjectBeatsAStubStandingInForIt` | |
| Be told when a built-in SID had no domain to scope it by | `MembershipNestingPassTests.ABuiltinSidWithNoDomainIsCounted` | |
| Read a derivation back: what it recorded, its phases, and how much it holds | `DerivationReadingTests` | |
| Be refused a store written by a build whose schema differs, with the reason | `DerivationReadingTests.Stage2a_AStoreFromAnotherSchemaIsRefused` | |
| Tell a phase that did not run from one that failed, reading back | `DerivationReadingTests.Stage2a_APhaseThatDidNotRunIsNotAFailure` | |
| See what a derivation produced rather than how far its pass read | `NewAuditViewModelTests.WhatTheDerivationProducedIsReported` | 2026-08-28 |
| Have a sealed bundle derived from without asking for it | `NewAuditViewModelTests.EvidenceThatWasSealedIsDerivedFromWithoutBeingAskedFor` | |
| Be certain deriving happens before judging | `NewAuditViewModelTests.DerivingHappensBeforeJudging` | |
| Still have the evidence judged when the derivation could not be done | `NewAuditViewModelTests.ADerivationThatCouldNotBeDoneDoesNotStopTheJudging` | |
| Read back what a derivation did not cover, not only what it found | `DerivationReadingTests.Stage2a_APartialDerivationReadsBackAsPartial` | 2026-08-28 |
| Be told which budget stopped a closure short, after the run has ended | `DerivationReadingTests.Stage2a_TheLimitThatStoppedTheExpansionComesBack` | 2026-08-28 |
| Tell a domain nobody could reach from one left out, reading a store back | `DerivationReadingTests.Stage2a_ADomainThatCouldNotBeReachedDoesNotReadBackAsOneLeftOut` | 2026-08-28 |
| Have a derivation that covered everything say so rather than say nothing | `DerivationWritingTests.Stage2a_ACompleteDerivationStillRecordsThatItIsComplete` | 2026-08-28 |
| Derive a bundle again without reading the forest a second time | `CommandLineTests.DerivingNamesTheBundle` | 2026-08-28 |
| Not get a capture he did not ask for by mistyping a derive | `CommandLineTests.DerivingIsNotCombinedWithARunLibrary` | 2026-08-28 |
| Have every type this stage publishes held to the same rules as the rest of the product | `SurfaceRegisterTests` | 2026-08-28 |
| Not meet two methods called `Expand` that answer unrelated questions | `ConceptRegistryTests` | 2026-08-28 |
| See the protected set his own forest enforces, not the one Microsoft publishes | `ProtectedCatalogueExclusionTests.Stage2a_AnExcludedGroupIsNotProtected` | 2026-08-28 |
| Tell a group his forest excluded from one that was never protected | `ProtectedCatalogueExclusionTests.Stage2a_ThePublishedSetIsStillAnswerableAfterNarrowing` | 2026-08-28 |
| Not be told the protected set is in doubt when his forest answered clearly | `ProtectedCatalogueExclusionTests.Stage2a_AForestThatExcludedNothingSaysItWasAsked` | 2026-08-28 |
| Keep every published protection where a bundle cannot say what the forest set | `ProtectedCatalogueExclusionTests.Stage2a_ABundleWithoutTheValueKeepsThePublishedSet` | |
