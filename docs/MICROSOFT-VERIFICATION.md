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

**Defects found: 11 of 127.** All eleven were in `SchemaGuidCatalog`, and seven of those were in
the 74 entries nothing had ever checked. The two components verified since were clean.

## Not yet verified

Ordered by what a wrong value would do, not by how many there are. A value that produces a
plausible but false statement about an account ranks above one that makes the product fall over,
because the second tells you.

| Component | Values | Microsoft source | What a wrong value would do |
|---|---|---|---|
| `UserAccountControlWording` | 26 | `ADS_USER_FLAG_ENUM`, adschema a-useraccountcontrol | Miss every account that does not require Kerberos pre-authentication, or flag clean ones. No symptom either way |
| `PermissionWording` | 21 | `ADS_RIGHTS_ENUM` | Say "Read Properties" where the directory grants "Write Properties" |
| `DangerousPermissionClassifier` | 8 | MS-ADTS 5.1.3.2, control access rights | Wrong verdict on what is a takeover |
| `GroupTypeWording` | 6 | `ADS_GROUP_TYPE_ENUM` | Report a security group as a distribution group, losing every finding about its membership |
| `Sid` | 3 | MS-DTYP 2.4.2 | Name the wrong group as Tier 0 |
| `PermissionScope` | 4 | MS-ADTS 5.1.3.2 | Judge a right at the wrong scope |
| `DirectoryTime` | 1 | Interval syntax, `accountExpires` | Show a real-looking date that is wrong, or read "never" as an expiry |
| Group Policy parsers | 14 | MS-GPSB, MS-GPPREF | Wrong policy settings reported for one GPO |
| `SecurityDescriptorParser` | 10 | MS-DTYP 2.4.6 | Parsing throws - loud, so lower priority |
| `CaptureSearchRequestFactory` | 1 | LDAP control OID | The query is rejected - loud |

## What this register cannot tell you

A test pins a **number**. It cannot judge a **sentence**. `UserAccountControlWording` carries a
plain-English description for each flag, and no check can say whether that description is a fair
one for an administrator reading a report. That judgement is the owner's, and the wording is put
in front of him rather than assumed.
