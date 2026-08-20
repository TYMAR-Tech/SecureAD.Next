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

| | | |
|---|---|---|
| `F-S44-2` | **A closed loop of tests hid fifteen missing attributes.** The document matches the code, the code matches the rules, the rules match the document — every check passing in both directions, with the whole circle anchored to the set of rules already written. A rule nobody wrote is an attribute nobody misses. Security descriptor parsing and the sixty-two rule cards were *ported* and have external anchors; the catalogue was *reassembled* and had none. Proposed remedy: a reconciliation fixture requiring every predecessor attribute to be present or named in a written list of deliberate omissions. | open |
| `F-S44-1` | `0051`'s trust attributes were decided and never captured — `trustedDomain` was absent from the class map and `git grep` found `trustAttributes` nowhere in `next/`. | closed as a decision by [`0065`](../decisions/0065-the-catalogue-recovers-what-the-rebuild-dropped.md); implementation still owed |
| — | `0065` itself is decided and unimplemented, and the delay is not free: every run taken before it lands is permanently silent on those attributes | open |
