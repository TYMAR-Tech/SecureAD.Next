# Run identity and coverage

**Code:** `next/src/SecureAD.Evidence/Run/ProfileId.cs`, `CoverageId.cs`, `RunCoverage.cs`,
`DomainCoverage.cs`, `ForestPartitionCoverage.cs`, `SysvolCoverage.cs`, `GpoCoverage.cs`
**Layer:** Evidence — which audit this is, and how much of the forest it actually read.

[`what-a-bundle-holds.md`](what-a-bundle-holds.md) describes the evidence database and
[`the-bundle-on-disk.md`](the-bundle-on-disk.md) the files around it. This page is about the two
questions that have to be answered before a bundle can be set beside another one: **which forest and
which evidence is this**, and **what did the run manage to read**. Whether two runs may then be
compared is [`whether-two-runs-compare.md`](whether-two-runs-compare.md).

Was bound by RunIdentityDocumentationTests, a documentation gate retired on 2026-09-11,, which compares four outcome tables below against the four
enums in both directions. A member in the code and not here fails the build, and so does a member
here and not in the code. Every `Type.Member` written in backticks is resolved against the type it
names.

---

## Two identities, and only one of them can be recomputed

`ProfileId` answers *which forest*. `CoverageId` answers *which evidence*. Two runs are like for
like when both match.

`ProfileId.ForForest` is the only factory and it is a pure function of the forest name, so any
caller holding that name can rebuild the value rather than store it — which is what lets a bundle
whose metadata was never written still land in the right group. It carries `ProfileId.Value`,
sixteen lowercase hex characters, and `ProfileId.ForestFqdn`, the lowercased name that was hashed,
kept so a reader can see what produced the value instead of being shown a hash and asked to trust
it.

**A second factory is the failure this type is shaped to prevent.** The predecessor had one taking a
separate forest root distinguished name, nothing checked that name was the forest name's transform,
and two callers could compute different profiles for one forest. Such a run matched nothing, sat in
a group of one, was never offered as a compare partner, and said nothing about why.

`CoverageId` cannot be recomputed. It hashes the domains the forest reported, and can only be read
back from where the run recorded it. **That is why the two are separate types.** A combined identity
would force a half-populated value at exactly the sites that recompute the profile, and a wrong key
there silently groups runs that must not be compared.

The width and the alphabet are fixed because the value is used in folder names, log lines and
comparisons, all of which are awkward to change later.

## What the coverage identity hashes, and what it does not

**It hashes what the forest reported, not what the run managed to read.** A controller dying at hour
two must not give the run a private identity and strand it on a comparison island of one. Whether
the declaration was achieved is a different question — `RunCoverage` answers it — and a run that
failed to read a domain is refused a comparison outright, so the failure is *reported* rather than
hidden inside a key that no longer matches.

`CoverageId.ForDomainsExcluding` is the general factory: the domains the forest declared, and the
ones the run deliberately left out. `CoverageId.ForDomains` is the whole-forest case that excludes
nothing. Both carry `CoverageId.Value` and `CoverageId.ForestFqdn`. The forest name is part of the
identity as well as of the profile, so a bundle copied in by hand from another machine is not
offered as a partner for a forest it does not belong to.

**Both sets reach the hash, per
[`0052`](../../decisions/0052-the-domain-is-the-only-unit-of-scope.md).** Two runs of an eight-domain
forest, one leaving out domain three and one leaving out domain five, would otherwise both declare
all eight and hash alike — so the product would offer them as like for like and report the
difference between two entirely different domains as drift. Until 2026-08-21 nothing here did that.

**Hashing only the covered remainder would not do either.** A forest that genuinely shrank to seven
domains, and an eight-domain forest with one left out, cover the same ground and are not the same
evidence: one estate has seven domains and the other has eight and did not look at one.

Order, case and repeats are discarded before hashing, because the order discovery happened to return
the domains in is not a fact about the forest. A blank domain is refused outright — a hash computed
over a blank entry differs from one computed without it, so two runs of one forest would stop being
comparable on nothing. A run that declared no domain at all is refused: it assessed nothing, and
giving it an identity produces a key that quietly groups every such run together as mutually
comparable. An exclusion naming a domain the forest never declared is refused rather than dropped,
because the pairing is a mistake at the call site.

**Changing what goes into this hash is a schema change**, and
[`0084`](../../decisions/0084-a-stored-fingerprints-recipe-is-pinned-to-the-schema-version.md) is why.
The value is stored as `bundle.coverage_id` and read back as the identity the run library groups on.
Change the recipe and every value computed afterwards differs from every value computed before,
while a sixteen-character hex string looks identical either way — so old and new runs draw as two
groups under one identical heading. Raise `BundleSchema.Version` in the same change, and the
old-recipe bundle is refused at open instead of reaching the library.

> The sibling hashes solve this the other way round on purpose. `AceSetHash` puts its version
> *inside* the value, and every descriptor hash has a canonicalization version stored beside it,
> because there the question is whether two values may compare *equal*. Here the question is whether
> a stale value may reach a screen, and those want opposite answers. Reading `AceSetHash` and
> copying it is what the first adjudication of `F-0079-6` did, and it was wrong for this
> requirement.

**The declared and excluded lists are kept behind the hash, and they are internal.** Gate 4 forbids a
public member handing back a collection from a type that cannot say whether it looked, because an
empty list and a failed query render as the same empty grid. The declared list can never be empty,
so the ambiguity cannot arise there — but that is a fourth kind of exemption, and the allowlist says
plainly that a reason which is not *a compiled table that cannot fail* does not belong in it.
Widening an allowlist is how a gate dies. Callers outside the assembly read the same domains from
`RunCoverage.Domains`, which carries `RunCoverage.AllDeclaredUnitsAreComplete` beside them and is
therefore able to say whether it looked.

> The predecessor also hashed a list of operator-chosen organisational-unit exclusions. Those are
> gone for good: `0052` reads everything below a domain whole, so there is nothing smaller than a
> domain to exclude. `S-18` said flatly that there are no exclusions at all and cited `0017` for it.
> That was true when it was written and stopped being true at `0052`.

## What became of each declared domain

`DomainCoverage` records one domain's fate, carrying `DomainCoverage.DomainFqdn`,
`DomainCoverage.Outcome` and `DomainCoverage.Reason`. The reason is null only for a domain that was
read, because a domain that was read has nothing to explain; every other factory requires one,
since a refusal that names no cause is a refusal an operator cannot act on.

Four factories produce the five outcomes: `DomainCoverage.Read`, `DomainCoverage.PartiallyRead`,
`DomainCoverage.NotRead`, and `DomainCoverage.Excluded`, which takes an `ExclusionKind` and chooses
between the two exclusion outcomes from it.

<!-- DOMAIN-OUTCOMES:BEGIN -->

| Outcome | What it means | Counts as read |
|---|---|---|
| Read | The domain was read in full | yes |
| PartiallyRead | The domain was reached and part of it was read | no |
| NotRead | We tried and could not | no |
| ExcludedByChoice | We did not look, under an operator's attestation | no |
| ExcludedForWantOfCandidates | The forest named nothing to look at | no |

<!-- DOMAIN-OUTCOMES:END -->

**A partially read domain counts as failed, and that is the decision rather than an omission.** It
is tempting to treat it as a smaller success — most of a domain is more than none of it — and that
is the reasoning this type exists to refuse. A domain read in part is a hole of unknown shape.
Nothing downstream can see its edges, so a later comparison against it reports fewer changes than
really happened while looking exactly like a comparison that found nothing.

**A domain left out is not a domain that failed, and neither is a domain nothing could reach.**
[`0063`](../../decisions/0063-excluded-never-looks-like-unreachable.md) holds the three apart wherever
any of them appears. *We did not look*, *the forest named nothing to look at*, and *we tried and
could not* have three different remedies, and the last may be the most important thing the run
found. A domain the forest cannot serve is a network, trust or decommissioning problem worth an
administrator's attention; an exclusion is a decision the operator already knows about.

**The cause lives in the outcome, not only in the reason text.** `0063` requires a reader of
coverage to tell a choice from an unreachable domain without opening another table, and prose in
`DomainCoverage.Reason` cannot be counted, compared or queried.

## A forest is not only its domains

The configuration partition and the schema partition belong to the forest rather than to any domain,
so `RunCoverage.Of` takes their outcomes as a separate argument. Per
[`0035`](../../decisions/0035-coverage-is-recorded-once-per-capture-unit.md) a run that cannot read one
of them has *failed*, rather than having found a domain with a problem — expressed as domain
coverage it would make a forest-wide failure look local, and expressed nowhere, which is where it
was until this existed, a failed schema read left every domain still reporting as read.

**That is not hypothetical.** Per
[`0014`](../../decisions/0014-capture-reads-the-schema-partition.md) an unread schema partition is the
failure that stops any permission being resolved at all, so it is precisely the one that must not
pass quietly.

`ForestPartitionCoverage.Read` and `ForestPartitionCoverage.NotRead` are the two factories, carrying
`ForestPartitionCoverage.NamingContextDn`, `ForestPartitionCoverage.Kind`,
`ForestPartitionCoverage.Outcome` and `ForestPartitionCoverage.Reason`. The outcome is a
`ForestPartitionReadOutcome`.

`ForestPartitionCoverage.Kind` is a `NamingContextKind` — `Domain`, `Configuration` or `Schema` —
and it lives in the Evidence layer rather than beside the capture that reads a partition, because a
coverage record has to say what kind of partition it describes long after the capture ended. The
capture page [`the-search-capture-issues.md`](../audit/the-search-capture-issues.md) names it to
point here and does not claim it.

<!-- PARTITION-OUTCOMES:BEGIN -->

| Outcome | What it means |
|---|---|
| Read | The partition was read in full |
| NotRead | The partition could not be read |

<!-- PARTITION-OUTCOMES:END -->

**There is no third member here, where `DomainReadOutcome` has five, and the omission is the
decision.** A domain is many partitions and can genuinely be partly covered. Each of these is one
capture unit, and a unit either completed — producing its row — or failed and ended the run. A
`PartiallyRead` here would describe a state capture cannot reach.

**A domain partition is refused.** Recording one here would put a single naming context into two
coverage models at once, which is the disagreement `0035` was written to end.

**Both partitions are required, with no overload that omits them.** Every forest has exactly one of
each, so unlike the domain list their denominator is known without discovery — which means silence
can be refused outright rather than merely noticed. `RunCoverage.Of` counts each kind and throws
unless it was reported exactly once. A default of *none reported* would let a run that never looked
at the schema partition pass as complete.

## Group Policy, the one read that may fail without failing the run

`RunCoverage.Sysvol` is the third thing held beside the domains, and it is unlike the other two.
Group Policy settings live in files on a share rather than in the directory, and per
[`0044`](../../decisions/0044-sysvol-coverage-is-recorded-beside-the-capture-units.md) **a failure to
read them does not fail the run.** It is the first and only exception to fail-fast capture
([`0003`](../../decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md)), taken because permission
problems on a file share are ordinary and a run that died over one policy folder out of four hundred
would be unusable in the field.

**The tempting shortcut is to mark the domain partly read instead, and `DomainCoverage` says plainly
why that is wrong.** A partly read domain counts as an outright failure, so one unreadable policy
folder would make the whole forest audit unusable as a baseline. That is not *the run does not
fail*; it is the run failing one step later, somewhere the operator cannot connect to the cause.

**Why SYSVOL is allowed to record coverage at all.** `0035` gives that right to capture units alone.
`0044` widens it by exactly one clause: a thing that is not a capture unit may record coverage only
where its incompleteness has knowable edges. SYSVOL qualifies because the policy list comes from
LDAP before a single file is opened, so a run that could not read three folders out of four hundred
knows which three, by name and identifier. **A record that said *partial* without naming them would
fail the condition it was admitted under** — which is why `SysvolCoverage.UnreadablePolicies` exists
and why `SysvolCoverage.Of` will not accept a nameless failure.

`SysvolCoverage.Of` sets the policy outcomes against the policies the directory declared, refusing a
policy reported twice — two outcomes for one policy means the capture disagrees with itself about
what it read. It carries `SysvolCoverage.Policies`, every declared policy in display-name order read
or not, `SysvolCoverage.UnreadablePolicies`, `SysvolCoverage.Outcome`,
`SysvolCoverage.AllDeclaredPoliciesAreComplete`, and the pair a report puts in front of a reader —
`SysvolCoverage.PoliciesDeclared` and `SysvolCoverage.PoliciesRead`, *397 of 400 policies were
examined*. Both are stated rather than left derivable, because a figure assembled at each call site
is a figure that will eventually be assembled differently at one of them.

`SysvolCoverage.Outcome` is a `SysvolReadOutcome`, derived from the policies rather than supplied,
so it cannot disagree with the list it summarises and a caller cannot declare success over a set of
failures.

<!-- SYSVOL-OUTCOMES:BEGIN -->

| Outcome | What it means |
|---|---|
| Read | Every policy the directory declared was read in full |
| PartiallyRead | Some policies were read and some were not, or some only in part |
| NotRead | The directory declared policies and none of them could be read |

<!-- SYSVOL-OUTCOMES:END -->

**`NotRead` is reserved for a forest that declared policies and yielded none**, because that usually
means the share itself was refused rather than one folder, and it is the case an operator must act
on immediately. **A forest with no policies at all reports `Read`**: there was nothing to read and
nothing was missed, and calling that a failure would make every empty test forest look broken.

`SysvolCoverage.AllDeclaredPoliciesAreComplete` is what vouches for the list under gate 4 — a caller
holding it can tell a short one from a complete one without inspecting every element. It is coarser
than the outcome and does not replace it: false covers both *three policies out of four hundred were
missed* and *the share refused everything*, and those call for different action.

Each policy is a `GpoCoverage`, carrying `GpoCoverage.GpoGuid`, `GpoCoverage.DisplayName`,
`GpoCoverage.FileSysPath`, `GpoCoverage.Outcome` and `GpoCoverage.Reason`. The policy is named as
well as identified, and both are deliberate: the GUID is what the evidence joins on, and the display
name is what an administrator recognises. A report naming three unreadable policies by GUID alone
has told him something is wrong without telling him what to go and look at. The outcome is a
`GpoReadOutcome`.

<!-- GPO-OUTCOMES:BEGIN -->

| Outcome | What it means |
|---|---|
| Read | Everything this product reads from the policy's folder was read |
| PartiallyRead | Some of the policy's files or folders were read and some were not |
| Unreadable | Nothing in the policy's folder could be read |

<!-- GPO-OUTCOMES:END -->

**The middle member is the point of the whole record.** A partition is one capture unit and is read
or is not; a policy is a folder tree, and a run that read its settings but was refused the
permissions on its scripts folder has done neither. Collapsing that into `Read` would tell a
customer his policy was examined when a third of it was not.

There are four factories over those three outcomes. `GpoCoverage.Read`, `GpoCoverage.PartiallyRead`
and `GpoCoverage.Unreadable` each take the folder on the share. `GpoCoverage.Unlocatable` records a
policy the directory declared **without saying where its files are** — a `groupPolicyContainer`
whose `gPCFileSysPath` did not come back, either because the attribute is absent or because the
reader was not allowed it. It reports `Unreadable` with a null path, and it is recorded rather than
dropped from the denominator, because a policy quietly removed from the list of what should have
been read is precisely the hole `0044` requires to have edges.

**The reason is never invented.** It is what the file system said — access denied, the path is not
there, the share did not answer. Since a SYSVOL failure does not end the run, that text is the only
account of it that will ever reach an operator.

## Setting the outcomes against the declaration

`RunCoverage.Of` is the only way to build one. It takes the declaration, the domain outcomes, both
forest partitions and the SYSVOL result, and carries `RunCoverage.Declared`, `RunCoverage.Domains`,
`RunCoverage.ForestPartitions`, `RunCoverage.Sysvol`, `RunCoverage.IncompleteDomains`,
`RunCoverage.UnreadForestPartitions` and `RunCoverage.AllDeclaredUnitsAreComplete`.

**It refuses two disagreements between the declaration and the outcomes, in both directions.**

- **A reported domain that was never declared.** Capture and discovery disagree about what the
  forest is, and choosing which of them to believe is not this type's business.
- **A declared domain with no outcome at all.** This is the dangerous one: it is a domain nobody
  looked at, and treating that silence as success is the single defect this product cannot have.

`RunCoverage.IncompleteDomains` and `RunCoverage.UnreadForestPartitions` are kept separately so a
refusal can name them. An operator told only that his run is unusable has been told *what*, and not
what to fix.

### `AllDeclaredUnitsAreComplete` is an internal check, and is never shown as coverage

It is literally *every declared domain has an outcome saying it was read, and both forest partitions
were read*. It was called `IsComplete` until `F-S29-3`, while being consulted as though it were a
statement about a customer's forest.

**In any bundle a reader can open, it is true.** Capture is fail-fast, so a domain that could not be
read returns before the seal, and a declared domain with no recorded outcome makes `RunCoverage.Of`
throw. It cannot report a forest that was partly read, because no such bundle exists.

**An excluded domain makes it false, and that is not a failure.** An exclusion is not a read, so a
run that legitimately left a domain out reports false here while being perfectly sound. Read as
*this run may not be a baseline* it would be wrong, since `0052` reintroduced exclusion and `0069`
gave each scope its own baseline.

> `RunCoverage`'s own remark used to say that incompleteness was guaranteed away by refusing to
> seal, which taken with this definition would have meant a run with any exclusion could never seal
> at all. It can; the bundle has a table for storing exclusions. Corrected 2026-08-21.

**It is kept because it is the enforcement of a rule, not because it varies.**
[`0027`](../../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) says a run
that did not read every domain it set out to read may not be a baseline and may not be compared.
Today that is guaranteed upstream. This is what would catch a bundle written by some future second
path — controller failover, parallel capture, anything re-analysis-shaped — that produced a hole.
Removing it would leave the rule stated and unenforced.

**SYSVOL is deliberately outside it.** A SYSVOL failure does not fail the run, so
`SysvolCoverage.AllDeclaredPoliciesAreComplete` genuinely varies between bundles while this flag is
true in all of them. Merging the two converts an always-true invariant into a customer-facing
verdict, which is the defect `F-S29-3` was raised about. A future session proposing to unify them
should read `0044` first.

**The name takes the `*AreComplete` shape deliberately.** It says the *record* of the declared units
is exhaustive — the same sense `PartitionCoverage.ContinuationReferencesAreComplete` carries one
level up — rather than claiming a forest was fully read.

## What a run covered is stated by the rows, not by the flag

What a run covered is reported from the partition rows and from the unread-partition list, both of
which vary by forest. Presenting an always-true flag as a coverage verdict is `F-S29-3` one level
up, and it is the reason this page separates *what was declared*, *what was read* and *whether the
record of it is exhaustive* into three different things with three different names.

---

## What is built

**The test is the evidence; this table is only the index.**

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank means
unit-tested but not yet exercised against Active Directory.

These three rows came from the area file the-run-library.md when it was deleted on 2026-08-24. They
were left behind by that pass and restored the same day, after an audit of what the deleted file
had carried; the page owns `CoverageId`, so they belong here.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| be certain two runs leaving out different domains are not treated as alike | `CoverageIdTests.LeavingOutADifferentDomainIsDifferentEvidence` |  |
| be certain a run with a domain left out is not compared against a whole-forest one | `CoverageIdTests.LeavingADomainOutIsNotTheSameAsReadingTheWholeForest` |  |
| see runs of one scope grouped together, and a later run of that scope join them | `CoverageIdTests.RunsGroupByWhichDomainsTheyCovered` | 2026-08-21 |
| see a run that read every domain called complete, and only then | `RunCoverageTests.ARunThatReadEveryDomainIsComplete` |  |
| be certain a domain that was never read makes the whole run incomplete | `RunCoverageTests.ADomainThatWasNotReadAtAllMakesTheRunIncomplete` |  |
| be certain a domain read only in part counts as failed, not as read | `RunCoverageTests.ADomainReadOnlyInPartCountsAsFailed` |  |
| read the reason a domain was incomplete, beside the fact that it was | `RunCoverageTests.AnIncompleteDomainCarriesTheReasonItWasIncomplete` |  |
| be certain a domain read in full carries no reason, so a reason always means something | `RunCoverageTests.ADomainReadInFullCarriesNoReason` |  |
| be certain a forest-wide partition that went unread makes the run incomplete | `RunCoverageTests.AForestPartitionThatWasNotReadMakesTheRunIncomplete` |  |
| be certain coverage cannot be reported for a domain the forest never declared | `RunCoverageTests.ReportingOnADomainThatWasNeverDeclaredIsRefused` |  |
| be certain a declared domain cannot be left with no outcome at all | `RunCoverageTests.ADeclaredDomainWithNoOutcomeIsRefused` |  |
| see which Group Policy objects a run missed, named rather than counted | `SysvolCoverageTests.TheRecordNamesThePoliciesThatWereMissed` |  |
| see how many policies were read against how many there were | `SysvolCoverageTests.TheCountsAreTheDenominatorAndTheNumerator` |  |
| be certain a policy read only in part makes the SYSVOL read partial | `SysvolCoverageTests.APolicyReadOnlyInPartAlsoMakesTheReadPartial` |  |
| be certain a policy with no declared path is still counted rather than dropped | `SysvolCoverageTests.APolicyWithNoDeclaredPathIsStillCounted` |  |
| be certain no production code can mark a capture unit unread by hand | `UnreadOutcomeIsUnreachableTests.NoProductionCodeRecordsAUnitAsUnread` |  |
| be certain that check reads the real production source and would notice | `UnreadOutcomeIsUnreachableTests.TheScanReadsTheRealProductionSource` |  |

---

> **Where this came from.** `S-18` held all of the above and the comparability verdict as well, and
> was deleted when this page and [`whether-two-runs-compare.md`](whether-two-runs-compare.md) were
> written. Its `STATES` table had already moved to [`the-bundle-on-disk.md`](the-bundle-on-disk.md).
> `S-18`'s gate listed eleven types where the document described seventeen: `ForestPartitionCoverage`,
> `SysvolCoverage`, `GpoCoverage` and their three enums were named in the prose and bound by nothing,
> so the four tables on this page are new binding rather than moved binding. That is `P-19`'s shape
> again — a check narrower than the document it was named for.
