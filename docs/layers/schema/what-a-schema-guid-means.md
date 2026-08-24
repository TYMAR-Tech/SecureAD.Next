# What a schema GUID means

**Layer document.** `next/src/SecureAD.Kernel/Schema/` — four files, 532 lines, read whole.

Active Directory scopes a permission by GUID. When the directory records that somebody may write an
attribute or exercise an extended right, it writes down a GUID and nothing else.
`bf967a68-0de6-11d0-a285-00aa003049e2` is not readable, and it is the difference between a
permission that matters and one that does not — it is `userAccountControl`, which is how an account
is turned into one that does not need a password. Without a table, an audit tool can report only
that a principal holds a permission over something opaque, which is not a report anyone can act on.

This folder is that table.

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** These rows were also carried in the governing area file docs/areas/what-a-permission-means.md.
*They were copied rather than moved because a gate required that file to keep its* What is built
*table permanently. That gate was deleted on 2026-08-21 (`P-51`), and the area file itself was
deleted on 2026-08-24 without its capability rows being copied anywhere, so these are now the only
copy rather than one of two.*

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank means
unit-tested but not yet exercised against Active Directory.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| see a right named rather than shown as a bare identifier | `SchemaGuidCatalogTests.WhenAGuidHasOneMeaning_ThenTheLookupReturnsExactlyOneEntry` |  |
| be certain an identifier with several meanings returns all of them | `SchemaGuidCatalogTests.WhenOneGuidHasTwoMeanings_ThenTheLookupReturnsBoth` |  |
| be certain an unknown identifier is reported as unknown rather than as nothing | `SchemaGuidCatalogTests.WhenTheGuidIsUnknown_ThenTheLookupIsEmptyRatherThanNull` |  |
| be certain an identifier shipped wrong once is never resolved to again | `SchemaGuidCatalogTests.WhenAGuidWasShippedWrongOnce_ThenTheCatalogueDoesNotResolveToItAgain` |  |
| see which catalogue version named a right | `SchemaGuidCatalogTests.WhenTheCatalogueIsRead_ThenItStatesItsVersion` |  |
| be certain the schema catalogue has a single source | `SchemaGuidSingleSourceGateTests` |  |
| be certain a name the product ships is the name Microsoft publishes | `SchemaGuidCatalogMicrosoftAnchorTests.WhenMicrosoftPublishesAnEntry_ThenTheCatalogueAgreesWithIt` |  |
| be certain no shipped name was invented rather than published | `SchemaGuidCatalogMicrosoftAnchorTests.WhenANameWasInvented_ThenTheCatalogueDoesNotDefineIt` |  |
| be certain no shipped row escaped the check against Microsoft | `SchemaGuidCatalogMicrosoftAnchorTests.WhenAnEntryIsShipped_ThenAPinnedRowNamesIt` |  |
| be certain the table cannot be altered after the product starts | `SchemaGuidCatalogTests.WhenTheCatalogueIsInspected_ThenItOffersNoWayToChangeIt` |  |
| be certain a forest's own attribute is named by the forest and not guessed | `SchemaGuidCatalogTests.WhenProvenanceIsExpressed_ThenCapturedIsAvailableToSayToo` |  |
| be certain what a rule specification names and what the table holds agree | `SchemaGuidCatalogTests.WhenARuleSpecificationNamesAGuid_ThenTheCatalogueAgreesWithIt` |  |

---

## The types

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `SchemaGuidCatalog` | The table. One table, two indexes, plus property-set membership |
| `SchemaGuidEntry` | One row: `Guid`, `LdapName`, `Kind`, `Source`, and nothing else |
| `SchemaGuidKind` | What a GUID names — and it is a property of the row, not of the GUID |
| `SchemaGuidSource` | Whether the name was shipped or read from a forest |

<!-- TYPES:END -->

They declare the namespace `SecureAD.Kernel.Schema`.

`SchemaGuidEntry` carries identity and provenance and nothing else. **Two fields the tables this
folder replaced did carry are deliberately absent, and a reader who does not find out why will put
one back.** `IsDangerous` is gone because whether a right is dangerous is a judgement rather than a
fact — the reasoning is under *Do not change* below, and it is stronger than a layering argument.
`DisplayName` is gone because the directory holds the authoritative label and capture reads it, per
[`0014`](../../decisions/0014-capture-reads-the-schema-partition.md); nobody has to author those
strings, and inventing presentation copy with no stated provenance is how a catalogue starts
drifting. Until a screen shows a captured label, a report renders `User-Force-Change-Password`. That
is a temporary coarseness, not a design position.

---

## What a lookup answers

Every member states what it gives back when it knows nothing, because a caller that guesses which
convention a member follows is a caller that will read an absent answer as a present one.

<!-- MEMBERS:BEGIN -->

| Member | Answers | When it knows nothing |
|---|---|---|
| `Embedded` | The catalogue shipped with the product | — |
| `CapturedOver` | A catalogue answering from a forest's own schema first, falling back to a shipped one | captured entries empty gives the shipped table alone |
| `HasCapturedEntries` | Whether any answer came from a forest rather than the shipped table | `false` |
| `Entries` | Every row, in declaration order | — |
| `Version` | Which table produced a name | — |
| `FindByGuid` | Every meaning this GUID can carry | an empty list, never `null` |
| `FindByLdapName` | The one entry with this name | `null` |
| `GuidFor` | The GUID for a name | `null` |
| `MembersOfPropertySet` | The attributes a forest puts in a property set | `null`, meaning *not known* — never an empty list |
| `Guid` | On a row: the `rightsGuid` or `schemaIDGUID`, lowercase and without braces | — |
| `LdapName` | On a row: the name Microsoft's AD schema gives it | — |
| `Kind` | On a row: what this GUID names | — |
| `Source` | On a row: whether the name was shipped or read from a forest | — |

<!-- MEMBERS:END -->

### Looking up by GUID returns a set, on purpose

One GUID can mean more than one thing. `bf9679c0-0de6-11d0-a285-00aa003049e2` is both the
`Self-Membership` validated write and the `member` attribute;
`72e39547-7b18-11d1-adef-00c04fd8d5cd` is a validated write, a property set and an attribute. Which
one an access control entry means is decided by the entry's own type, not by the GUID.

Both tables this folder replaced resolved such a GUID to whichever row was declared first and said
nothing about the other. That is a lookup answering a question it was not asked, quietly. Returning
the set makes the ambiguity visible to the caller that can actually settle it.

### `null` and empty are different answers, and both occur

`MembersOfPropertySet` returns `null` when no forest schema was read and a list when one was. The
two are not the same claim: `null` is *nobody looked*, and an empty list would be *the set is
empty*. A caller must not read the first as the second — the classifier's whole contract is that an
unassessed permission is never reported as safe.

Only the forest can answer this at all. A property set names none of its members; each attribute
points back at the set through `attributeSecurityGUID`, so a customer can put their own attribute
into a Microsoft-defined set. There is no shipped fallback, and inventing one would call a set
harmless while the directory disagreed.

---

## The two layers

The table here is the **shipped** layer: base-schema GUIDs, the same in every forest, available
offline and without a capture. It is not the whole answer. Every real forest carries schema
extensions — vendor products, and locally created attributes whose GUIDs are generated at creation
and unique to that forest — which no shipped table can contain.

Those come from the **captured** layer, read from the schema partition during capture per
[`0014`](../../decisions/0014-capture-reads-the-schema-partition.md). `CapturedOver` is that two-layer
lookup. Callers ask one lookup, not two: if a caller had to choose which catalogue to consult, some
caller would choose wrong and another would consult neither and write a GUID literal, which is
exactly the history this folder replaces.

**The forest wins, and that is the point of capturing it.** A shipped name is a general claim about
Active Directory; a captured one is a fact about the forest under audit on the day it was read.
Where they disagree an administrator can act on the second.

**Entries are deduplicated, not concatenated.** Both layers certainly name `userAccountControl`, and
the name index is unique, so concatenating would throw on construction. A GUID already answered for
by the captured layer, under the same kind or the same name, does not gain a second shipped answer
behind it.

**`Unclassified` is the exception to *the forest wins*, because it is not an answer.** It means the
forest published a `controlAccessRight` whose `validAccesses` was absent or unreadable, so this
build cannot say which of the three kinds sharing the extended-rights container it is. Such an entry
yields to any entry of either layer that classifies the same GUID. Without that, a well-known
extended right whose forest row happens to carry no `validAccesses` would take the name and suppress
the shipped classification, turning a `Dangerous` verdict into `CannotClassify` — a false negative
created by the fix for a false positive.

Only captured evidence produces `Unclassified`. Every row in the shipped table was classified by
hand, and `WhenTheShippedTableIsRead_ThenNothingInItIsUnclassified` asserts none carries it.

`HasCapturedEntries` exists so a screen can say which of the two kinds of claim it is making. A run
refused the schema partition resolves only what Microsoft publishes, which is a smaller answer and
not a complete one.

### Where this folder ends and Evidence begins

**`CapturedSchemaGuidReader` is Evidence's, not this folder's, and that was decided before drafting
rather than during it.** It is the only producer of `SchemaGuidSource.Captured` entries anywhere in
the product, so it is named here — but its mechanics are not described here, and it is deliberately
absent from this document's component tables.

Three facts decide it. It is `internal` to `SecureAD.Evidence`. Every line of its body reads a
bundle: it takes a `SqliteConnection`, builds its query from `BundleSchema.ColumnNameFor`, selects
from `captured_object`, and decodes a `schemaIDGUID` octet string whose byte order is the trap. And
the dependency runs one way — it has `using SecureAD.Kernel.Schema`, while nothing in this folder
references it and nothing here could. The rewrite is one document per code folder, and its folder is
`SecureAD.Evidence`.

**The cost of that ruling is stated rather than hidden.** Evidence closed at five documents and none
of them covers this file, so today it is documented in neither layer. That is carried as an open
item rather than settled by absorbing it here, because a type documented in two layers is the
failure that split `S-18`, and a pass that quietly widened its own scope to avoid an awkward
remainder would be choosing the larger error.

What this folder does own is the **contract** the captured layer must satisfy: that a captured entry
states its source, that an unclassified one yields, and that property-set membership has no shipped
fallback. Those are asserted here. How a bundle yields such an entry is Evidence's to describe.

---

## What the shipped table holds

Counted from `SchemaGuidCatalog.cs` rather than recalled: **101 rows over 97 distinct GUIDs.**

<!-- KINDS:BEGIN -->

| Kind | Rows | What it names |
|---|---|---|
| `ExtendedRight` | 38 | A control access right, such as `User-Force-Change-Password` |
| `ValidatedWrite` | 5 | A validated write, such as `Self-Membership` |
| `PropertySet` | 15 | One name covering a group of attributes |
| `Attribute` | 30 | A single schema attribute, such as `userAccountControl` |
| `ObjectClass` | 13 | A schema object class, such as `user` |
| `Unclassified` | 0 | A control access right this build could not classify — captured evidence only |

<!-- KINDS:END -->

Three GUIDs carry more than one row — `bf9679c0` twice, `f3a64788` twice, and
`72e39547` three times — which is the directory's doing and not a defect: repetition *across* kinds
is Active Directory, and repetition *within* one kind would be two rows claiming the same fact and
fails the build.

Names are the CN Microsoft's AD schema reference gives, so an entry can be checked against
`learn.microsoft.com/windows/win32/adschema` one line at a time — and it has been. All 101 rows are
pinned in `SchemaGuidCatalogMicrosoftAnchorTests` in both directions: every shipped entry must have
a pinned row and every pinned row must be shipped, so neither an unchecked addition nor a silent
removal survives. See [MICROSOFT-VERIFICATION](../../MICROSOFT-VERIFICATION.md) and
[`0077`](../../decisions/0077-a-well-known-sid-is-named-from-microsoft.md).

**That harvest is why `Version` is 2.** Eleven of a hundred entries were wrong and every test over
the table had passed for months. Three of the corrections are worth naming, because each is a shape
that will recur:

| Was shipped as | Actually | How it was found |
|---|---|---|
| `DS-Replication-Get-Changes-All-Extended` on `fec364e0` | `Do-Garbage-Collection`; the name was not an extended right at all | absent from Microsoft's Extended Rights index |
| `DS-Replication-Manage-Topology` on `1131f6ab` | `1131f6ab` is `DS-Replication-Synchronize`; the right one is `1131f6ac` | a neighbouring GUID, one digit out |
| `DS-Replication-Monitor-Topology` on `ee914b82` | `ee914b82` is `Abandon-Replication`; the real GUID was absent entirely | the name was published under another right's GUID |

The second missed every DCShadow grant while reporting benign ones. The third meant a real
monitor-topology grant resolved to nothing. **A transposed pair between neighbouring GUIDs is the
characteristic defect of a hand-curated table, and nothing internal can find it** — only reading
Microsoft's page for each entry can, which is what the anchor test now pins.

---

## Do not change

**Nothing here says whether a right is dangerous.** A GUID's name and kind are facts about Active
Directory: true whether or not this product exists, checkable against Microsoft's schema reference,
and the same for every customer. Whether a permission is dangerous is a judgement this product
makes, it depends on the mask and the entry type as well as the GUID, and it belongs to the
classifier — see [permission classification](../kernel/permission-classification.md) and
[`0010`](../../decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md).

**The reason is stronger than the layering argument, and it is the one to keep.** Danger is a
property of the *set* of rights a principal holds, and a per-GUID boolean cannot express a pair:

| A principal holds | Consequence |
|---|---|
| `DS-Replication-Get-Changes` alone | ordinary replication; not secrets |
| `Get-Changes` + `Get-Changes-All` | full DCSync — every password hash in the domain |
| `Get-Changes` + `Get-Changes-In-Filtered-Set` | the filtered set, which is a product judgement rather than a documented fact — see [`0016`](../../decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md) |
| `Get-Changes-All` alone | not usable on its own |

The old table flagged two of that family and left the third alone. **No setting of a per-GUID
boolean could have been correct.** The same holds from the other direction for `gPLink` and
`scriptPath`: write access to either runs code across everything in scope, while read access to both
is unremarkable. Mask and target tier decide it, and the table sees neither.

**The catalogue cannot change once built, and this is prevented by construction rather than by
discipline.** Its predecessor was a static mutable singleton into which a schema capture merged
entries behind a lock, so the same GUID could resolve differently depending on what had already run
in the process — and once an overlay was loaded there was no way to ask for the shipped answer at
all. For a product whose whole value is that two runs can be compared, a classification that varies
with process history is a provenance hazard. The type has no mutating member, and a catalogue read
from a live schema is a second instance rather than an edit to this one.

**A rule names an attribute, never a GUID literal.** `GuidFor` exists for that, and
`SchemaGuidSingleSourceGateTests` makes it a build failure rather than a convention: the old product
wrote GUID literals in five production files, and the same attribute ended up recorded under three
different GUIDs, two of them wrong. A correct catalogue nothing is obliged to use does not become
the source of truth by being correct.

---

## What is owed

Every claim in this section was checked against the code rather than carried across, because a claim
that something is *not built* is the least-verified sentence in this repository — nothing resolves
the name of a thing that does not exist. Three claims inherited from the consumed slice document
were false and have been dropped rather than repeated: that the dangerous set had no owner (the
classifier ships), that nothing depended on this folder (two callers do), and that the table had
never been checked against Microsoft entry by entry (it has, and eleven defects came out of it).

- **`Version` is recorded nowhere.** The constant says a bundle can state which table named its
  GUIDs, but no writer puts the value in one and no reader looks for it — unlike
  `canonicalization_version`, which `BundleReader.Open` does refuse a mismatch on. A bundle written
  before the eleven corrections and one written after are indistinguishable, so the names in the
  older one cannot be known to be the wrong ones. That is a gap in evidence provenance rather than
  in this folder, and it is `P-35`.
- **A shipped and a captured name disagreeing about a base-schema GUID is a finding, and nothing
  computes it.** [`0014`](../../decisions/0014-capture-reads-the-schema-partition.md) says so;
  `CapturedOver` resolves the display question and does not report the disagreement, though it is
  where the evidence would come from. `P-36`.
- **`CapturedSchemaGuidReader` is documented in no layer**, for the reason given above. `P-37`.
