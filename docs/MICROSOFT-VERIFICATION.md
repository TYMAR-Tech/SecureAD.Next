# Microsoft verification register

What in this product has been checked against Microsoft's own published values, when, and with
what. One row per component that carries values Microsoft defines.

**This file is an index, not evidence.** The evidence is the anchor test, which re-runs on every
build, and the harvest script, which re-reads Microsoft's page on demand. A row here that names
either falsely fails `MicrosoftVerificationRegisterTests`.

## Why a date, when the test runs continuously

The test and the date answer different questions.

- **The test** proves the code still matches the value that was pinned. It runs every build, so
  its answer is never stale.
- **The date** records when a human last confirmed that the pinned value is what Microsoft
  publishes. Nothing re-checks that automatically: Microsoft can revise a page, and a
  transcription can be wrong from the first day. The schema GUID catalogue had eleven wrong
  entries out of a hundred, and every test over it passed for months.

So a green build means *the code has not drifted*. Only the date says *the values were right in
the first place*.

## Verified

| Component | Values | Microsoft source | Harvested | Anchor test |
|---|---|---|---|---|
| `SchemaGuidCatalog` | 100 | AD Schema reference, per-entry pages | 2026-08-19 | `SchemaGuidCatalogMicrosoftAnchorTests` |
| `GenericRightsExpander` | 17 | MS-ADTS 5.1.3.2 | 2026-08-20 | `GenericRightsExpanderMicrosoftAnchorTests` |
| `AceType` | 10 | MS-DTYP 2.4.4.1 | 2026-08-20 | `AceTypeMicrosoftAnchorTests` |
| `WellKnownSidCatalog` | 88 | MS-DTYP 2.4.2.4 | 2026-08-20 | `WellKnownSidCatalogMicrosoftAnchorTests` |

**Defects found: 11 of 215.** All eleven were in `SchemaGuidCatalog`, and seven of those were in
the 74 entries nothing had ever checked. The three components verified since were clean.

`WellKnownSidCatalog` is new rather than pre-existing, so it could not have carried a defect. It is
recorded here because the values were harvested rather than written from memory, and because the
catalogue it replaces was not: the predecessor's hand-assembled table had `S-1-5-17` as
*This Organization* where Microsoft publishes `IUSR`, omitted `S-1-5-15` entirely, and used
`S-1-5-32-581` for Storage Replica Administrators where Microsoft publishes `S-1-5-32-582` and no
581 at all. Both errors were internally consistent and would have survived any test written from
that file. Two of the three checks in `WhenASidWasCarriedWrongBefore_ThenTheCatalogueCarriesMicrosoftsValue`
exist to stop either coming back.

## Not yet verified

Ordered by what a wrong value would do, not by how many there are. A value that produces a
plausible but false statement about an account ranks above one that makes the product fall over,
because the second tells you.

Counts are scanner hits from `next/tools/inventory-external-literals.ps1`. **They overstate the
work**: a value written once in an assignment and once in its XML comment counts twice, which is
why `AceType` showed 20 hits for 10 values.

| Component | Hits | Microsoft source | What a wrong value would do |
|---|---|---|---|
| `UserAccountControlWording` | 27 | `ADS_USER_FLAG_ENUM`, adschema a-useraccountcontrol | Miss every account that does not require Kerberos pre-authentication, or flag clean ones. No symptom either way |
| `PermissionWording` | 21 | `ADS_RIGHTS_ENUM` | Say "Read Properties" where the directory grants "Write Properties" |
| `DangerousPermissionClassifier` | 8 | MS-ADTS 5.1.3.2, control access rights | Wrong verdict on what is a takeover |
| `PermissionScope` | 8 | MS-ADTS 5.1.3.2 | Judge a right at the wrong scope |
| `GroupTypeWording` | 6 | `ADS_GROUP_TYPE_ENUM` | Report a security group as a distribution group, losing every finding about its membership |
| `Sid` | 3 | MS-DTYP 2.4.2 | Name the wrong group as Tier 0 |
| `DirectoryTime` | 1 | Interval syntax, `accountExpires` | Show a real-looking date that is wrong, or read "never" as an expiry |
| `EntryReach` | 1 | MS-ADTS 5.1.3.2 | Misjudge what an entry reaches |
| `SecurityTemplateParser` | 7 | MS-GPSB | Wrong security policy reported for a GPO |
| `GroupPolicyPreferenceParser` | 3 | MS-GPPREF | Wrong preference reported for a GPO |
| `GpoClientSideExtensionCatalog` | 2 | MS-GPOL client-side extension GUIDs | Attribute a setting to the wrong Group Policy component |
| `RegistryPolicyParser` | 1 | MS-GPREG | Wrong registry policy reported |
| `RestrictedGroup` | 1 | MS-GPSB restricted groups | Wrong membership policy reported |
| `ForestPartitions` | 4 | MS-ADTS crossRef `systemFlags` | Read the wrong partitions, so the run covers the wrong thing |
| `SecurityDescriptorParser` | 10 | MS-DTYP 2.4.6 | Parsing throws - loud, so lower priority |
| `ParsedAce` | 2 | MS-DTYP 2.4.4 | Parsing throws - loud |
| `CapturedAttribute` | 1 | adschema a-searchflags | Misjudge whether an attribute is confidential |
| `CaptureSearchRequestFactory` | 1 | LDAP control OID | The query is rejected - loud |

## Values the scanner cannot see

The scanner matches GUIDs, hex, OIDs and `S-1-` SIDs. Three kinds of external value escape it, and
each needs checking by hand rather than by count.

**Single-digit hex was invisible until 2026-08-20.** The pattern required two or more hex digits,
so `0x1` and `0x2` did not match. Fixing it revealed `ForestPartitions` - a file carrying four
Microsoft-defined values that had never appeared in any inventory - and doubled `PermissionScope`
from four hits to eight. Anything measured before that date understated the work.

**Attribute and class names, 48 of them.** `msDS-KeyCredentialLink`, `msLAPS-EncryptedDSRMPassword`,
`ms-Mcs-AdmPwdExpirationTime` and the rest are Microsoft's to spell. A misspelt attribute is simply
never returned by the directory, and nothing reports that it was missing - the object appears with
one fewer value and looks complete. This is the quietest failure in the product and no test
currently guards it.

**Behaviour that is not a value at all.** `lastLogonTimestamp` is deliberately coarse, by default up
to fourteen days stale; `lastLogon` does not replicate. `CapturedAttributeCatalog` records both
facts and acts on them correctly, but they are prose, and no harvest can pin a sentence.

## What this register cannot tell you

A test pins a **number**. It cannot judge a **sentence**. `UserAccountControlWording` carries a
plain-English description for each flag, and no check can say whether that description is a fair
one for an administrator reading a report. That judgement is the owner's, and the wording is put
in front of him rather than assumed.
