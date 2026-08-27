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

**Values** is how many the component holds now, not how many were checked on the harvest date. A
component that grows makes this number stale, and only re-reading the source refreshes the date
beside it. The two are separate facts and the column carries the first.

| Component | Values | Microsoft source | Harvested | Anchor test |
|---|---|---|---|---|
| `SchemaGuidCatalog` | 101 | AD Schema reference, per-entry pages | 2026-08-19 | `SchemaGuidCatalogMicrosoftAnchorTests` |
| `GenericRightsExpander` | 17 | MS-ADTS 5.1.3.2 | 2026-08-20 | `GenericRightsExpanderMicrosoftAnchorTests` |
| `AceType` | 10 | MS-DTYP 2.4.4.1 | 2026-08-20 | `AceTypeMicrosoftAnchorTests` |
| `WellKnownSidCatalog` | 88 | MS-DTYP 2.4.2.4 | 2026-08-20 | `WellKnownSidCatalogMicrosoftAnchorTests` |
| `UserAccountControlWording` | 22 | adschema a-useraccountcontrol, `ADS_USER_FLAG_ENUM`, KB 305144 | 2026-08-21 | `UserAccountControlWordingMicrosoftAnchorTests` |
| `ProtectedGroupCatalogue` | 15 | Appendix C: Protected Accounts and Groups in Active Directory | 2026-08-27 | `ProtectedGroupCatalogueMicrosoftAnchorTests` |

**Defects found: 12 of 238.** Eleven were in `SchemaGuidCatalog`, seven of those in the 74 entries
nothing had ever checked. The twelfth is below, and it was a **missing** value rather than a wrong
one.

`UserAccountControlWording` is where this register learned that counting sources is not the same as
having them. It was first checked against adschema and `ADS_USER_FLAG_ENUM`, which agreed on
twenty-one flags - and that was recorded here as two independent reads. **It was one lineage read
twice:** both pages descend from `iads.h`. KB 305144 is maintained separately, and it publishes a
twenty-second bit, `0x04000000`, marking a read-only domain controller. The product had no word for
it, so an RODC's account rendered a raw hexadecimal number where a sentence belongs.

Nothing internal could have found this. The anchor test as first written listed twenty-one
published bits and would have rejected the correct flag as invented - a check anchored to the wrong
reference, passing in both directions, which is `F-S44-2` exactly. The third source was reached only
because an archived document, `S-57`, cited it. **Ask what a set of checks is anchored to, not only
whether each one is sound.**

`WellKnownSidCatalog` is new rather than pre-existing, so it could not have carried a defect. It is
recorded here because the values were harvested rather than written from memory, and because the
catalogue it replaces was not: the predecessor's hand-assembled table had `S-1-5-17` as
*This Organization* where Microsoft publishes `IUSR`, omitted `S-1-5-15` entirely, and used
`S-1-5-32-581` for Storage Replica Administrators where Microsoft publishes `S-1-5-32-582` and no
581 at all. Both errors were internally consistent and would have survived any test written from
that file. Two of the three checks in `WhenASidWasCarriedWrongBefore_ThenTheCatalogueCarriesMicrosoftsValue`
exist to stop either coming back.

`ProtectedGroupCatalogue` is where this register was used to settle a question the specification had
recorded as unanswerable, which is a use it had not been put to before.

`docs/layers/specs/JUDGEMENT-HALF.md` gated two edge kinds in the protected-principal derivation on
the grounds that no Microsoft source stated whether the protection process follows them. For
distribution nesting one does, and it is the same page the specification already quotes for the
adjacent claim: *Reducing the Active Directory Attack Surface* states that an account with
transitive membership in a protected group inherits the restricted security **regardless of whether
the membership is derived from security or distribution groups**, gives the nested distribution
group as its worked example, and says distribution groups are included in protected group member
enumeration for exactly that reason. The sentence the specification did quote - that such an account
receives no token SID - is the next one along.

**The gate was not wrong to exist; it was wrong about what had been read.** Both halves were on one
page, and the specification's own preamble says as much about an earlier miss: *both were one page
fetch away*. What this register adds is that the finding is now written down with its date, so the
next reader does not re-open the question or, worse, implement the edge from inference.

It is recorded as documentation rather than specification. Appendix C and the attack-surface guidance
are product documentation, not Open Specifications, and `ProtectedEdgeProvenance` keeps the three
strengths of claim apart so the weakest can be revisited when something better turns up. The primary
group half of the same gate, `AC-64`, remains unevidenced and unfollowed.

## Not yet verified

Ordered by what a wrong value would do, not by how many there are. A value that produces a
plausible but false statement about an account ranks above one that makes the product fall over,
because the second tells you.

Counts are scanner hits from `next/tools/inventory-external-literals.ps1`. **They overstate the
work**: a value written once in an assignment and once in its XML comment counts twice, which is
why `AceType` showed 20 hits for 10 values.

| Component | Hits | Microsoft source | What a wrong value would do |
|---|---|---|---|
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

**That happened on 2026-08-21, and it is what the numeric check missed.** Every bit was right and
four sentences were still in question. The owner decided each one:

- `0x00000100` now carries Microsoft's full text. The clause it had dropped says the account
  reaches **this domain only and not domains that trust it** - a clause that *disproves* a
  cross-domain worry, so omitting it pointed an auditor at a risk the flag prevents.
- `0x00002000` says *domain controller* where the two ADSI pages say *backup domain controller*,
  which is Windows NT vocabulary. This was first recorded here as a deliberate divergence from
  Microsoft. It is not one: KB 305144 words the bit as "a computer account for a domain controller
  that is a member of this domain". The wording follows Microsoft; the earlier note was wrong
  because it had only read two thirds of Microsoft.
- `0x00000040` and `0x00000001` are open findings in
  [`PUNCH-LIST.md`](PUNCH-LIST.md) — `P-65` and `P-66` — not corrections. Microsoft says one cannot
  be set directly and the other does not work over LDAP, which would make both sentences claims the
  bit cannot support. Neither is reworded until a lab run says what real accounts carry.

No test would have raised any of the four, and the harvest script is deliberately silent on wording
for the same reason.
