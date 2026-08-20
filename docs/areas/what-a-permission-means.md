# What a permission means

**Area.** How the product reads a permission off an object and decides what it lets somebody do:
expanding shorthand rights, naming the thing a right applies to, and judging which permissions are
dangerous. This is the core of what the product knows.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| treats nothing inherited as definitive, because inheritance can be blocked or replaced | `0033` |
| says so when a DACL could not be read, rather than reporting no permissions | [`0037`](../decisions/0037-an-unreadable-dacl-says-so.md) |
| records whether a DACL arrived in canonical order, because order changes the answer | [`0038`](../decisions/0038-a-descriptor-records-whether-its-dacl-was-canonical.md) |
| never requests the audit portion of a descriptor | [`0036`](../decisions/0036-capture-never-requests-the-sacl.md) |
| withholds a verdict at the widest scope that shares it, rather than repeating it | [`0005`](../decisions/0005-withhold-at-the-widest-scope-that-shares-the-verdict.md) |
| keeps one source for schema identifiers, so a right is named the same way everywhere | [`0014`](../decisions/0014-capture-reads-the-schema-partition.md) |
| holds the rule catalogue as data and the rule logic as code | [`0010`](../decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md) |
| keeps Tier 0 and expected-administrator as two separate sets | [`0006`](../decisions/0006-tier-0-and-expected-admin-are-separate-sets.md) |

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** A capability whose test does not exist, or does not pass, fails the build — so nothing
here can claim something the product does not do.

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank is the
honest answer for most rows and means unit-tested but not yet exercised against Active Directory -
a test with a synthetic descriptor proves the parser handles those bytes, not that a domain
controller sends them.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|---|
| be certain a shorthand "full control" right is expanded to what it actually grants | `GenericRightsExpanderTests.WhenGenericAllIsSet_ThenTheFullSpecificMaskReplacesIt` |  |  |
| be certain a shorthand write right is expanded before it is judged | `GenericRightsExpanderTests.WhenGenericWriteIsSet_ThenWritePropertyReplacesIt` |  |  |
| be certain shorthand and specific rights on one entry both survive expansion | `GenericRightsExpanderTests.WhenGenericAndSpecificAreMixed_ThenBothSurvive` |  |  |
| be certain an entry with no shorthand right is left alone | `GenericRightsExpanderTests.WhenNoGenericBitIsSet_ThenTheMaskIsUnchanged` |  |  |
| be certain a deny entry is ordered ahead of an allow, whatever order it arrived in | `AceNormalizerTests.WhenAllowPrecedesDenyOnTheWire_ThenDenySortsFirst` |  |  |
| be certain an explicit entry is ordered ahead of an inherited one | `AceNormalizerTests.WhenBothExplicitAndInherited_ThenExplicitSortsFirst` |  |  |
| be certain the same permissions produce the same fingerprint whatever order they arrived in | `AceNormalizerTests.WhenTheSameAcesArriveInEitherOrder_ThenTheCanonicalFormIsIdentical` |  |  |
| be certain a changed trustee changes the fingerprint | `AceNormalizerTests.WhenTheTrusteeDiffers_ThenTheHashDiffers` |  |  |
| be certain a changed right changes the fingerprint | `AceNormalizerTests.WhenTheAccessMaskDiffers_ThenTheHashDiffers` |  |  |
| be certain an inherited entry is not confused with an identical explicit one | `AceNormalizerTests.WhenTwoAcesDifferOnlyByInheritance_ThenBothSurvive` |  |  |
| tell an object with no permissions from one whose permissions could not be read | `AceNormalizerTests.WhenComparingANullDaclWithAnEmptyOne_ThenTheyAreDistinguishable` |  |  |
| be certain an absent DACL says so rather than reporting no entries | `AceNormalizerTests.WhenTheDaclIsNull_ThenNormalizationSaysSoRatherThanReportingNoAces` |  |  |
| be certain damage found while parsing is carried forward, not dropped | `AceNormalizerTests.WhenParsingReportedDamage_ThenNormalizationCarriesItForward` |  |  |
| be certain no damage is invented where parsing reported none | `AceNormalizerTests.WhenParsingReportedNoDamage_ThenNormalizationInventsNone` |  |  |
| be certain every entry records the canonicalization version that produced it | `AceNormalizerTests.WhenNormalized_ThenEachAceRecordsTheCanonicalizationVersionThatProducedIt` |  |  |
| be certain a permission to read a local administrator password is judged dangerous | `DangerousPermissionClassifierTests.ReadingALocalAdministratorPasswordIsDangerous` |  |  |
| be certain writing a policy link or a logon script is judged dangerous | `DangerousPermissionClassifierTests.WritingAPolicyLinkOrALogonScriptIsDangerous` |  |  |
| be certain an ordinary attribute read is not reported as dangerous | `DangerousPermissionClassifierTests.ReadingAnOrdinaryAttributeIsNotDangerous` |  |  |
| be certain an ordinary extended right is not reported as dangerous | `DangerousPermissionClassifierTests.AnOrdinaryExtendedRightIsNotDangerous` |  |  |
| be certain every verdict the classifier can give is exercised and named | `DangerousPermissionClassifierTests.TheCheckExercisesEveryVerdictAndTheCatalogueKnowsTheNames` |  |  |
| see a right named rather than shown as a bare identifier | `SchemaGuidCatalogTests.WhenAGuidHasOneMeaning_ThenTheLookupReturnsExactlyOneEntry` |  |  |
| be certain an identifier with several meanings returns all of them | `SchemaGuidCatalogTests.WhenOneGuidHasTwoMeanings_ThenTheLookupReturnsBoth` |  |  |
| be certain an unknown identifier is reported as unknown rather than as nothing | `SchemaGuidCatalogTests.WhenTheGuidIsUnknown_ThenTheLookupIsEmptyRatherThanNull` |  |  |
| be certain an identifier shipped wrong once is never resolved to again | `SchemaGuidCatalogTests.WhenAGuidWasShippedWrongOnce_ThenTheCatalogueDoesNotResolveToItAgain` |  |  |
| see which catalogue version named a right | `SchemaGuidCatalogTests.WhenTheCatalogueIsRead_ThenItStatesItsVersion` |  |  |
| read the same account of classification in the document and the code | `PermissionClassificationDocumentationTests` |  |  |
| read the same account of descriptor parsing in the document and the code | `SecurityDocumentationTests` |  |  |
| be certain the schema catalogue has a single source | `SchemaGuidSingleSourceGateTests` |  |  |

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This section is the owner's to write.** What follows is a draft list of candidates, offered so
there is something to react to. It is not authoritative and nothing here has been decided.

- **What the product says about a permission that is dangerous but expected.**
  [`0006`](../decisions/0006-tier-0-and-expected-admin-are-separate-sets.md) separates the two sets;
  what an operator sees where they meet is undrawn.
- **How effective permissions are presented** — what a principal can actually do to an object once
  denies, inheritance and group membership are all taken together.
- **Whether the product judges ownership**, which grants control regardless of the DACL.
- **How a permission held through a group is attributed** — to the group, to the member, or to both.

---

## Open findings

| | | |
|---|---|---|
| — | none recorded for this area yet | — |
