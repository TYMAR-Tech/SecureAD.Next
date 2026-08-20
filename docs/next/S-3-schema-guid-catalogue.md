# S-3 — The schema-GUID catalogue

**Type:** slice
**Reviewed at commit:** working tree, session S-3
**Size:** 3 files, 268 lines, plus 2 test files
**Date:** 2026-08-10

## What it does

Says what a GUID in an access control entry means.

When Active Directory records that somebody may write an attribute or exercise an extended right,
it writes down a GUID and nothing else. `bf967a68-0de6-11d0-a285-00aa003049e2` is not readable, and
it is the difference between a permission that matters and one that does not — it is
`userAccountControl`, which is how an account is turned into one that does not need a password.
Without a table, an audit tool can report only that a principal holds a permission over something
opaque, which is not a report anyone can act on.

`SchemaGuidCatalog` is that table. `SchemaGuidEntry` is a row. `SchemaGuidKind` says what sort of
thing a row names.

## Why the two inventory rows became one component

K13 and K14 were both hand-curated tables of Active Directory schema GUIDs.

| | K13 `GuidCatalog` | K14 `WellKnownGuids` |
|---|---|---|
| Folder | `Core/Catalogs/` | `Core/Schema/` |
| Direction | GUID → meaning | name → GUID, and GUID → entry |
| Row type | `GuidCatalogEntry` | `SchemaGuidEntry` |
| Kind enum | `GuidCategory` | `GuidType` |
| Extra field | `IsDangerous` | `DisplayName` |

They overlapped in content, differed in coverage, and neither referenced the other; exactly one
file in the whole product touched both. Both carried correction comments about entries that had
previously pointed at the wrong GUID. **Two tables of the same facts is two places to be wrong and
two places to fix, and the comments show it had already happened in both.**

The map's own conclusion, which these rows answer, is one sentence long: *"One table, two
indexes."*

The merge is not cosmetic. The two LAPS password attributes that rule SEC-090 reads —
`ms-Mcs-AdmPwd` and `msLAPS-Password` — were in K14 and absent from K13. A caller that asked K13
whether it knew them got "no". Recorded as F-S3-1.

## Shape

| Member | Answers | Absent input |
|---|---|---|
| `Embedded` | The catalogue shipped with the product | — |
| `CapturedOver` | A catalogue answering from a forest's own schema first, falling back to a shipped one | captured entries empty gives the shipped table alone |
| `HasCapturedEntries` | Whether any answer came from a forest rather than the shipped table | `false` |
| `MembersOfPropertySet` | The attributes a forest puts in a property set | `null`, meaning not known — never an empty list |
| `Version` | Which table produced a name, so a bundle can record it | — |
| `Entries` | Every row, in declaration order | — |
| `FindByGuid` | Everything this GUID can mean | an empty list |
| `FindByLdapName` | The one entry with this name | `null` |
| `GuidFor` | The GUID for a name | `null` |

`CapturedOver` is the two-layer lookup
[`0014`](../decisions/0014-capture-reads-the-schema-partition.md) specified. The forest's answer
wins, because a shipped name is a general claim about Active Directory and a captured one is a fact
about the forest under audit. Entries are deduplicated by GUID-and-kind and by name rather than
concatenated: both layers name `userAccountControl`, and the name index is unique.

`SchemaGuidKind.Unclassified` is the exception to *the forest's answer wins*, because it is not an
answer. It means the forest published a `controlAccessRight` whose `validAccesses` was absent or
unreadable, so this build cannot say which of the three kinds sharing the extended-rights container
it is. Such an entry yields to any entry of either layer that classifies the same GUID: without
that, a well-known extended right whose forest row happens to carry no `validAccesses` would take
the name and suppress the shipped classification, turning a `Dangerous` verdict into
`CannotClassify` — a false negative created by the fix for a false positive, which is `F-S54-2`.

The kind exists because guessing was worse. Until `S-58` finding `#13`, an unrecognised value became
`ExtendedRight`, on the reasoning that it is the reading which grants most; `S-53` carries that
decision and its amendment. The reasoning is right for a severity judgement and wrong for this,
because the kind selects which rule computes the verdict — a property set called an extended right
is judged by `ClassifyExtendedRight` and never reaches `ClassifyPropertySetWrite`. Only captured
evidence produces the member; every row in the shipped table was classified by hand, and a test
asserts none of them carries it.

`HasCapturedEntries` exists so a screen can say which of the two kinds of claim it is making. A run
refused the schema partition resolves only what Microsoft publishes, which is a smaller answer and
not a complete one.

`MembersOfPropertySet` answers what a property set actually grants, and returns `null` rather than an
empty list when no forest schema was read. The two are different answers: `null` is *nobody looked*,
and an empty list would be *the set is empty*. Only the forest can answer this at all — a property
set names none of its members, each attribute points back at the set through `attributeSecurityGUID`,
and a customer can therefore put their own attribute into a Microsoft-defined set. There is no
shipped fallback, and inventing one would call a set harmless while the directory disagreed.

`SchemaGuidEntry` carries four things and no more: `Guid`, `LdapName`, `Kind`, `Source`.

`SchemaGuidSource` says whether a name was shipped with the product or read from a forest. A name
in a report is a claim, and the two claims are not equally strong: *Microsoft publishes this GUID as
`userAccountControl`* can be checked by anyone, while *your forest says this GUID is
`contoso-PayrollId`* is true of that forest on that day and nowhere else. Per
[`0014`](../decisions/0014-capture-reads-the-schema-partition.md) the evidence distinguishes them
rather than presenting both as the same kind of fact.

#### This is one layer of two

The table here is the **shipped** layer: base-schema GUIDs, the same in every forest, available
offline and without a capture. It is not the whole answer. Every real forest carries schema
extensions - vendor products, and locally created attributes whose GUIDs are generated at creation
and unique to that forest - which no shipped table can contain.

Those come from the **captured** layer, read from the schema partition during capture per
[`0014`](../decisions/0014-capture-reads-the-schema-partition.md). Callers ask one lookup, not two:
if a caller had to choose which catalogue to consult, some caller would choose wrong and another
would consult neither and write a GUID literal, which is exactly the history this component
replaces.

#### Looking up by GUID returns a set, on purpose

One GUID can mean more than one thing. `bf9679c0-0de6-11d0-a285-00aa003049e2` is both the
`Self-Membership` validated write and the `member` attribute; `72e39547-7b18-11d1-adef-00c04fd8d5cd`
is a validated write, a property set and an attribute. Which one an access control entry means is
decided by the entry's own type, not by the GUID.

Both previous tables resolved such a GUID to whichever row was declared first — `WellKnownGuids`
says so in a comment, *"First entry wins if duplicates exist"* — and said nothing about the other.
That is a lookup answering a question it was not asked, quietly. Returning the set makes the
ambiguity visible to the caller that can actually settle it.

#### Nothing here says whether a right is dangerous

This is the line the session was asked to draw, and it is drawn where
[`0010`](../decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md) draws it.

**A GUID's name and kind are facts about Active Directory.** They are true whether or not SecureAD
exists, they can be checked against Microsoft's schema reference one line at a time, and they are
the same for every customer. That is data.

**Whether a permission is dangerous is a judgement SecureAD makes.** It depends on the access mask
and the entry type as well as the GUID — `WriteProperty` scoped to `userAccountControl` is one
thing, `ReadProperty` scoped to the same attribute is another — and it is what the product is
staking its reputation on when it tells a customer they have a problem. That is code, and it is
inventory row K16, which already exists as a **Rebuild** row for exactly this reason: the map found
**five** places answering "is this right dangerous" and they did not agree with each other.

So `IsDangerous` does not come across. K16 will hold the dangerous set and will name its entries by
LDAP name through this catalogue rather than repeating GUID literals — which is how the same
attribute came to be written down under three different GUIDs, two of them wrong. Recorded as
F-S3-2 so the obligation is visible rather than assumed.

`DisplayName` does not come across either, for the mirror-image reason: it is presentation copy
that no part of a run reads, which is the half of a catalogue that drifts. F-S3-3.

## Dependencies

- **Depends on:** nothing. `string`, `FrozenDictionary` and an array. No directory, no database, no
  clock, no Windows.
- **Depended on by:** nothing yet. The register names K16 as the row expected to bring the first
  consumer, because classifying a right is the first thing that has to know what a GUID means.
- **Layering violations:** none.

## Where it lands

`SecureAD.Kernel`, namespace `SecureAD.Kernel.Schema`. `next/README.md` already names schema GUIDs
as part of the kernel's subject, alongside security descriptors and distinguished names, so this is
the register catching up with a decision already written down.

Both previous folders are dropped. `Catalogs/` was named for a shape rather than a subject, and
`Schema/` in this codebase meant both *the directory's schema* and *the storage format* — the map
records that collision separately, under K20.

## Checked against `docs/rules/`

Eight GUIDs are written down in a rule specification. Where a specification names one, the
specification is the source of truth and the test's expected value is taken from it, not from the
old code.

| GUID | Named by | Agreed? |
|---|---|---|
| `member` | SEC-006 §3 | yes |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` | SEC-014 | yes |
| `Certificate-Enrollment` | SEC-040 | yes |
| `Certificate-AutoEnrollment` | SEC-041 | yes |
| `ms-Mcs-AdmPwd`, `msLAPS-Password` | SEC-090 | K14 yes; **K13 did not have them** |
| `sIDHistory` | SEC-123 | yes |
| `DS-Replication-Manage-Topology` | SEC-124 | yes |

`WhenARuleSpecificationNamesAGuid_ThenTheCatalogueAgreesWithIt` holds all eight.

Three values are recorded in the specifications as having been shipped wrong, and each caused a
rule to miss the attack it existed to find while reporting benign grants instead:
`bf967a6d` (`userParameters`) and `9a9a0220` (`userSharedFolderOther`) for `sIDHistory`, and
`1131f6ab` (`DS-Replication-Synchronize`) for `DS-Replication-Manage-Topology`.
`WhenAGuidWasShippedWrongOnce_ThenTheCatalogueDoesNotResolveToItAgain` asserts the catalogue does
not resolve to any of them.

## Verified-safe

- **Nothing here reaches a directory, a disk or a clock.** Every member is a pure lookup.
- **The catalogue cannot change once built.** Its predecessor was a static mutable singleton:
  `LoadOverlay` merged schema-captured entries into a process-wide dictionary behind a lock, so
  `IsDangerous(guid)` could give different answers in the same process depending on whether a
  capture had already run, and once an overlay was loaded there was **no way to ask for the shipped
  answer at all**. For a product whose whole value is that two runs can be compared, a
  classification that varies with process history is a provenance hazard. It is now prevented by
  construction rather than by discipline — the type has no mutating member, which
  `WhenTheCatalogueIsInspected_ThenItOffersNoWayToChangeIt` asserts, and a catalogue read from a
  live schema will be a second instance rather than an edit to this one.
- **Every LDAP name is unique.** Asserted, and enforced a second time by the name index refusing to
  build over a duplicate. A repeated name would leave one row unreachable with nothing saying which.
- **No GUID is repeated within one kind.** Repetition *across* kinds is Active Directory and is
  tested for explicitly; repetition within a kind would be two rows claiming the same fact.
- **Every row is reachable through both indexes.** Asserted row by row, so an entry cannot be in the
  table and invisible to one of the two ways of asking.
- **Absence is empty or null, never a wrong answer.** An unknown GUID gives an empty list, not a
  first-declared guess; an unknown name gives `null`. A forest carries schema extensions this table
  has not heard of, and saying so is the correct answer.

**The guard binding this document was mutation-tested in both directions.** Directions observed are
recorded in F-S3-5.

## Findings

### F-S3-1 — One of the two tables did not know the LAPS attributes

- **Severity:** minor
- **Status:** CLOSED by the merge

SEC-090 detects who can read the local administrator password that LAPS stores, on either the
legacy `ms-Mcs-AdmPwd` attribute or the Windows LAPS `msLAPS-Password`. Both were in K14 and
neither was in K13, so "does the catalogue know this GUID?" had two answers and one of them was no.

Nothing was reported wrongly as a result — SEC-090 reads the GUIDs from its own SQL and not from
K13 — so this is minor rather than major. It is recorded because it is the concrete cost the map
predicted from keeping two tables, found rather than assumed.

Closed by there being one table.

### F-S3-2 — The dangerous set now has no owner until K16

- **Severity:** major
- **Status:** OPEN, owned by inventory row K16

K13 flagged nine GUIDs dangerous: `User-Force-Change-Password`, `DS-Replication-Get-Changes`,
`DS-Replication-Get-Changes-All`, `Self-Membership`, `Validated-SPN`,
`msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-KeyCredentialLink`, `userAccountControl`,
`unicodePwd`. That flag is deliberately not carried here, per §*Nothing here says whether a right is
dangerous*.

Filed as major because it is a real obligation and not merely a tidy-up. Until K16 lands, the
rebuild has a catalogue of what GUIDs mean and no statement anywhere of which of them matter, and
the nine names above are the thing that must not be quietly lost between the two rows.

Two of K13's own omissions should be settled while K16 is being written rather than inherited:
`DS-Replication-Get-Changes-In-Filtered-Set` was not flagged although it is part of the same
replication-rights family, and `gPLink` and `scriptPath` were present and flagged `false` although
one of the five old classifiers treated both as dangerous. Which is right is a security judgement,
which is why it belongs in K16 with a specification behind it and not in a table.

### F-S3-3 — Friendly display names are not carried

- **Severity:** minor
- **Status:** ANSWERED by [`0014`](../decisions/0014-capture-reads-the-schema-partition.md); no
  longer a gap in this component

K14 carried a `DisplayName` per row — "Replicating Directory Changes All", "Reset Password" — which
are the labels Windows itself shows. They are not carried here, and the original reasoning was that
presentation copy stored beside behavioural data is what
[`0010`](../decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md) separates.

**That reasoning was half right and reached the wrong conclusion.** Keeping copy out of the
behavioural table is correct. Treating the friendly label as decoration is not: the reader of an
audit report is an administrator who knows "Reset Password" from the Security tab and the delegation
wizard, and a report speaking a vocabulary its reader does not share is a report that does not land.

The resolution is that **nobody has to author these labels, because the directory holds them.**
"Reset Password" is the `displayName` attribute of the `User-Force-Change-Password` control access
right; attribute labels come from the display specifiers. `0014` makes capture read them alongside
the GUIDs, on the same queries, at no extra cost. A captured label has the best possible source —
the forest itself — which removes the original objection that inventing display strings with no
stated provenance is how a catalogue starts drifting.

Until capture lands, a report renders `User-Force-Change-Password`. That is a temporary coarseness,
not a design position.

### F-S3-6 — SEC-090 cannot see the replication route to LAPS passwords

- **Severity:** major
- **Status:** OPEN, owned by the rules work; verification in a lab forest outstanding

The LAPS rule looks for one thing: a principal holding read access **on the computer object**,
scoped to the `ms-Mcs-AdmPwd` or `msLAPS-Password` attribute GUID.

That is not the only way to read those attributes. Both are confidential and sit in the RODC
filtered attribute set, whose replication is governed by its own extended right —
`DS-Replication-Get-Changes-In-Filtered-Set`, `89e95b76-444d-4c62-991a-0facbeda640c`. Held together
with `DS-Replication-Get-Changes` at the domain head, it is a documented route to replicating that
set, LAPS passwords among them, **without a single ACE on any computer object.**

A principal holding those two rights can recover every local administrator password in the domain,
and the rule reports nothing. Not "could not compute" — nothing.

Filed as major because it is the failure an audit tool cannot make: silence where there is a live
credential-theft path. It is not raised as a stopping defect because it is a gap in the previous
product's rule and no rebuilt rule stands on it yet.

**This one wants confirming rather than believing.** The mechanics come from published research
rather than from anything in this repository. Granting a test principal exactly those two rights in
a lab forest and attempting the read would settle it, and that evidence is worth more than the
citation.

### F-S3-7 — Danger is a property of a set of rights, not of a GUID

- **Severity:** informational
- **Status:** CLOSED as reasoning; the obligation it creates is F-S3-2

The clearest justification for leaving `IsDangerous` out of the table, found after the decision
rather than before it:

| A principal holds | Consequence |
|---|---|
| `DS-Replication-Get-Changes` alone | ordinary replication; not secrets |
| `Get-Changes` + `Get-Changes-All` | full DCSync — every password hash in the domain |
| `Get-Changes` + `Get-Changes-In-Filtered-Set` | the filtered set, including LAPS passwords |
| `Get-Changes-All` alone | not usable on its own |

The old catalogue flagged two of that family and left the third alone. **No setting of a per-GUID
boolean could have been correct**, because the danger is a property of the combination a principal
holds and the table has one tick box per GUID and no way to express a pair.

The same is true from a different direction for `gPLink` and `scriptPath`: write access to either
runs code across everything in scope — and for `gPLink` the overlooked vector is *unlinking*, which
removes a hardening policy and needs no GPO-creation right at all — while read access to both is
unremarkable. Mask and target tier decide it, and the table sees neither.

So the flag did not merely belong in different code. It could not have been right in the shape the
table gave it.

### F-S3-4 — Two tables were merged by hand, and the union was not machine-checked

- **Severity:** minor
- **Status:** OPEN

The 100 rows were assembled by reading both previous tables and taking the union. The invariant
tests catch a duplicate, a malformed GUID, an empty name and an unreachable row, and the rule-
derived tests catch a disagreement with any GUID a specification names. **Nothing catches an entry
that existed in one of the old tables and was simply not copied across**, except for the eight
GUIDs the specifications name.

A test comparing the new table against the old ones would have caught it, and was not written on
purpose: it would bind the rebuild to code that is being deleted, and it would have to be deleted
with it. The honest mitigation is that this document names the count, and that anything a rule
actually reads is asserted from the rule.

### F-S3-5 — Mutation-testing record for the document guard

- **Severity:** informational
- **Status:** CLOSED, with one weakness recorded below

`SchemaGuidDocumentationTests` was mutated in three directions before being trusted. Every mutation
was reverted immediately after being observed, and the suite was confirmed green after each revert.

| Direction | Mutation | Result |
|---|---|---|
| Guard must fail when the code grows | added a public `KindCount` property to the catalogue | `TheDocumentNamesEveryPublicMemberOfTheComponent` failed, naming `KindCount` |
| Guard must fail when the document drops a member | removed the `FindByGuid` row from the shape table **and** its every other mention | the same test failed, naming `FindByGuid` |
| Guard must fail when it can see nothing | pointed the document path at a name that does not exist | all 18 failed, led by the scanner self-test, rather than passing vacuously |
| Guard must pass when code and document agree | reverted each mutation | 18 of 18 passed |

**The second direction found a weakness, and it is recorded rather than glossed.** The first attempt
at that mutation removed only the shape-table row, and the guard stayed green — because the table
above still contained the words `FindByGuid`, in the very row describing the row being removed. The
check asks whether a name appears *anywhere* in the document, not whether it appears in the table
that explains it. So a member could in principle be dropped from the shape table and remain
"described" by a passing mention elsewhere.

That is weaker than the guard's name suggests and worth knowing. It is not the failure mode that
stops work — the guard does catch a member the document does not mention at all, which is the drift
that actually happens — but a later session tightening this should make the check read the shape
table specifically. The same collision is why the first row above writes the mutated name without
backticks: written in the document's normal notation, the record of a mutation was enough to trip
the guard it describes.

An earlier attempt at the first direction was abandoned rather than reported: renaming `GuidFor` in
the kernel breaks the behaviour tests as well, so the run says nothing about the document guard in
isolation. Adding a member isolates it.

The substring weakness that S-2 found — a renamed member still matching by prefix — is avoided the
same way S-2 avoided it: names are matched in their backticked form, and a test asserts that
`GuidFor` is present while the same name with two characters appended is not.

## Open questions for the owner

- **Should `DS-Replication-Get-Changes-In-Filtered-Set` count as dangerous?** It is the third of the
  three DCSync-family replication rights and the only one the old catalogue did not flag. Granting
  it alone does not yield a full replica, which is presumably the reasoning, but it is a step
  towards one. This is a security judgement and belongs with K16.
- **Are `gPLink` and `scriptPath` dangerous?** Write access to either lets an attacker run code on
  every machine in scope, which is why one of the old classifiers said yes; the catalogue said no.
  Two of the five old answers disagreed on precisely these two names.
- **Does anything need the friendly display label?** If an export or a screen is going to show ACE
  scopes to a customer, F-S3-3 becomes a real gap and is cheap to close now.

## Not reviewed

- **Whether every one of the 100 rows matches Microsoft's schema reference.** Eight are asserted
  from rule specifications. The rest are carried with the correction comments that produced them,
  and were not independently re-verified against `learn.microsoft.com` line by line. That is the
  work F-S3-4 describes the limit of.
- **The schema-capture overlay.** K13's `LoadOverlay` fed the catalogue from a live schema
  partition, so a forest's own extensions could be named. Nothing equivalent is built here: it is
  capture work, it belongs to a capture row, and the shape it must take — a second catalogue
  instance whose size and source are recorded in the bundle — is stated above rather than left to
  be rediscovered.
- **Performance.** Not measured. Both indexes are `FrozenDictionary`, built once.
