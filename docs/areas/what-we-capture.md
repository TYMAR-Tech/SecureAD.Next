# What we capture

**Area.** What a run reads out of the directory: which partitions, which objects, which attributes on
them, and which security information is taken from each. Not how the run is started or how far it
got — those are their own areas.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| reads the whole forest, not a chosen corner of it | `0017` |
| reads the schema partition, so a permission can be named rather than shown as a GUID | [`0014`](../decisions/0014-capture-reads-the-schema-partition.md) |
| stores objects as typed columns, not as a bag of text | [`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md) |
| ships a noise list and excludes it from capture | [`0034`](../decisions/0034-capture-excludes-a-shipped-noise-list.md) |
| leaves DNS zones and records out of scope entirely | [`0042`](../decisions/0042-dns-zones-and-records-are-out-of-scope.md) |
| never asks for the SACL | [`0036`](../decisions/0036-capture-never-requests-the-sacl.md) |
| says so when a DACL could not be read, rather than recording an empty one | [`0037`](../decisions/0037-an-unreadable-dacl-says-so.md) |
| records whether each descriptor's DACL was in canonical order | [`0038`](../decisions/0038-a-descriptor-records-whether-its-dacl-was-canonical.md) |
| treats nothing inherited as definitive | `0033` |
| reads a GPO's file permissions below the root folder, not only on it | [`0043`](../decisions/0043-a-gpos-file-permissions-are-read-below-the-root-folder.md) |
| justifies a captured attribute by a rule that reads it, or a field of the object view it fills | [`0064`](../decisions/0064-an-attribute-is-justified-by-a-rule-or-the-object-view.md) |
| refuses to capture an attribute speculatively, for a rule nobody has written | [`0064`](../decisions/0064-an-attribute-is-justified-by-a-rule-or-the-object-view.md) |
| recovers the attributes the rebuild dropped, and captures the trust attributes `0051` decided on | [`0065`](../decisions/0065-the-catalogue-recovers-what-the-rebuild-dropped.md) |
| treats the filtered set and the replication route as a product judgement, not a mechanical read | [`0016`](../decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md) |

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
|---|---|---|
| be sure a partition larger than one page is read to the end | `PartitionCaptureTests.APartitionLargerThanAPageIsReadToTheEnd` |  |
| be certain the run never wanders to another controller by following a referral | `PartitionCaptureTests.AConnectionThatChasesReferralsIsRefusedBeforeAnyRequestIsSent` |  |
| be certain a connection that cannot say what the controller advertises is refused | `PartitionCaptureTests.AConnectionThatCannotSayWhatTheControllerAdvertisesIsRefused` |  |
| be certain an answer carrying no paging control is not mistaken for the last page | `PartitionCaptureTests.AnAnswerWithNoPagingControlIsNotTheLastPage` |  |
| be certain a controller that hands the same bookmark straight back is refused rather than looped | `PartitionCaptureTests.ABookmarkHandedStraightBackIsRefusedRatherThanResent` |  |
| see the objects a run could not follow reach the coverage record | `PartitionCaptureTests.ContinuationReferencesReachTheCoverageRecord` |  |
| be certain a busy controller is retried a bounded number of times and then the run ends | `PartitionCaptureTests.AControllerSayingItIsBusyIsAskedThreeTimesAndThenTheRunEnds` |  |
| be certain a cancelled capture stops rather than reporting itself finished | `PartitionCaptureTests.ACancelledCaptureStopsRatherThanFinishing` |  |
| get a group's full membership, past the limit a server will return in one response | `LdapEntryReaderTests.AGroupLargerThanTheServersValueLimitIsReadInFull` |  |
| be certain a first, partial response is never mistaken for the whole answer | `LdapEntryReaderTests.TheFirstResponseDoesNotClaimToBeAllOfThem` |  |
| tell an attribute that was absent from one that was present and empty | `LdapEntryReaderTests.AnAbsentAttributeIsNotReportedAsAnEmptyOne` |  |
| be certain a paged read that stalled is reported as a failure rather than an ending | `LdapEntryReaderTests.ABlockThatAdvancedByNothingIsAFailureAndNotAnEnding` |  |
| be certain the capture never asks the directory for a credential | `CredentialAttributeGuardTests.TheCatalogueNeverRequestsACredential` |  |
| be certain that guard is checking a real catalogue against a real list, not two empty ones | `CredentialAttributeGuardTests.TheGuardHasBothACatalogueAndAListToCheckItAgainst` |  |
| have the permissions **on** a credential object captured, while its secret is not | `CredentialAttributeGuardTests.ThePermissionsOnACredentialObjectAreStillCaptured` |  |
| have LAPS reported by when it last rotated, never by the password itself | `CredentialAttributeGuardTests.TheCatalogueTakesTheLapsTimestampAndNotTheLapsPassword` |  |
| be certain no attribute is asked for two different ways | `CapturedAttributeCatalogTests.NoAttributeIsDeclaredTwoDifferentWays` |  |
| be certain DNS is the only thing deliberately left out of the catalogue | `CapturedAttributeCatalogTests.TheDnsClassesAreTheOnlyOnesExcluded` |  |
| read a security descriptor the way the directory meant it | `SecurityDescriptorParserTests` |  |
| trust that permission normalisation has not silently changed | `GoldenAceHashTests` |  |
| have a GPO's files on SYSVOL read, and not only its directory object | `SysvolCaptureTests` |  |
| be certain every account state flag carries the bit Microsoft publishes for it | `UserAccountControlWordingMicrosoftAnchorTests` |  |

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This section is the owner's to write.** What follows is a draft list of candidates, offered so
there is something to react to. It is not authoritative and nothing here has been decided.

- **Whether the captured attribute catalogue is complete for the rules that will be written.**
  **Answered on 2026-08-16 by [`0064`](../decisions/0064-an-attribute-is-justified-by-a-rule-or-the-object-view.md)
  and [`0065`](../decisions/0065-the-catalogue-recovers-what-the-rebuild-dropped.md)**, after a
  comparison against the predecessor found fifteen attributes silently dropped. An attribute is now
  justified by a rule **or** by a field of the object view, and the catalogue recovers what was lost
  plus the trust attributes [`0051`](../decisions/0051-trusts-describe-a-boundary-and-never-widen-a-run.md)
  had already decided on. **None of it is implemented** — the catalogue, its version, the bound
  document and the derivation test are all still to change, and every run taken before that lands is
  permanently silent on those attributes.
- **Whether `ms-DS-MachineAccountQuota` and `dSHeuristics` are captured.** Offered and not taken on
  2026-08-16, recorded in `0065` so their absence is not read as a judgement. Both are standard
  audit findings sitting on objects already read.
- **Whether certificate services are captured.** Deliberately out under `0064`. The first run after
  that reverses is the first that can answer anything about certificate templates.
- **What happens when the schema declares an attribute the catalogue does not know.**
- **Whether a partial object — read, but with one attribute that failed — is stored, and how it is
  distinguished from a whole one.**
- **How much of a very large forest is expected to fit**, and what the product does when it does
  not.

---

## Open findings

**The catalogue findings moved to [`PUNCH-LIST.md`](../PUNCH-LIST.md) § Audit / Capture during the
documentation rewrite**, and the reasoning behind them now lives in
[the attribute catalogue](../audit/the-attribute-catalogue.md). `F-S44-2` is `P-20`, `0065`'s
unimplemented half is `P-21`, `F-S23-4` is `P-24` and `F-S23-5` is `P-25`. What remains here is the
account-state wording, which belongs to the Kernel and not to capture.

| | | |
|---|---|---|
| `F-0080-1` | **The product may say "The user cannot change the password." when it cannot know that.** Microsoft states on both pages that `0x00000040` cannot be set directly and that the real restriction is a permission entry on the account, so an account can carry the restriction with the bit clear. Our sentence would then be a confident false negative. Zero of 2,082 accounts in both lab bundles set the bit, which is consistent but proves nothing on its own. Lab check: in Active Directory Users and Computers, open a test user, Account tab, tick **User cannot change password**, apply. Take a capture, open that user in the product, and read the **What the account state says** card. If the sentence is absent while the box is ticked, the wording is misleading and must change. Severity deliberately unassigned pending the ramp (`F-0079-9`) | open |
| `F-0080-2` | **`ADS_UF_SCRIPT` may be a bit we word and the directory never sets.** Microsoft states the flag "does not work for the ADSI LDAP provider on either read or write operations", and capture reads over LDAP. If so, "The logon script is executed." is a sentence about a bit that carries no information. Zero of 2,082 accounts in both lab bundles set it. Lab check: in Active Directory Users and Computers, open a test user, Profile tab, set a **Logon script** name, apply. Take a capture and see whether that user shows the sentence. If a user with a logon script does not, the bit is not readable over LDAP and the entry should stop being worded. Severity deliberately unassigned pending the ramp (`F-0079-9`) | open |
| `F-0080-3` | **Closed on the evidence, and it was wrong when written.** This said `UserAccountControlWording.cs` cited an `S-57` that does not exist. `S-57` does exist - `S-57-adjudicating-the-deep-review.md`, archived on 2026-08-20 to the SecureAD Archive folder outside this repository. Its finding `#23` is real, is marked UPHELD, and says exactly what the code attributes to it. The citation was accurate; this finding was raised by searching the repository and treating absence there as absence anywhere | closed, no defect |
| `F-0080-4` | **Two Microsoft sources agreed and were the same source.** adschema and `ADS_USER_FLAG_ENUM` both descend from `iads.h`; their agreement was recorded as independent corroboration. KB 305144, maintained separately, publishes `PARTIAL_SECRETS_ACCOUNT` `0x04000000` - the read-only domain controller bit - which neither of the others carries and the product did not word. An RODC account rendered a raw hexadecimal number where a sentence belongs. The anchor test as first written would have rejected the correct flag as invented. Fixed 2026-08-21: flag added, all three sources now checked. Recorded because it is `F-S44-2` recurring in a component that was being verified *for* that fault, and the third source was reached only because an archived document cited it | closed, fixed |
| `F-0080-5` | **Closed: the query was wrong, the flag table is not.** A measurement suggested 2,068 of 2,082 accounts set a `userAccountControl` bit the product does not word. Grouping by distinct value settled it: 514 is disabled plus normal account, 66048 is normal plus password-never-expires, 2080 is interdomain trust plus password-not-required, 532480 is server trust plus trusted-for-delegation on the three domain controllers, and every remaining value decomposes into worded flags. **There are no unworded bits in either lab bundle.** Both versions of the mask expression were wrong; the per-flag counts taken minutes earlier were right and were the ones to believe | closed, no defect |
