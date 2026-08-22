# How a run is stored

**Area.** What a finished run leaves on disk: the bundle, its seal, how objects and their permissions
are written down, and what the product refuses to store. This is the boundary between reading a
directory and having evidence of it.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| treats the bundle as an output, never as a format something else writes | [`0013`](../decisions/0013-the-bundle-is-no-longer-a-two-way-contract.md) |
| carries a seal in every bundle | `0019` |
| uses that seal to detect corruption, and does not claim it detects tampering | [`0020`](../decisions/0020-the-seal-detects-corruption-not-tampering.md) |
| produces sealed evidence and never signed evidence | [`0030`](../decisions/0030-the-product-produces-sealed-evidence-never-signed.md) |
| stores objects as typed columns rather than as opaque blobs | [`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md) |
| writes a new bundle when a capture is analysed again, never editing the old one | [`0021`](../decisions/0021-re-analysis-produces-a-new-bundle.md) |
| keeps no backward compatibility with any earlier bundle shape | [`0001`](../decisions/0001-no-backward-compatibility.md) |
| records whether a descriptor's DACL was in canonical order | [`0038`](../decisions/0038-a-descriptor-records-whether-its-dacl-was-canonical.md) |
| stores that a DACL could not be read, rather than storing an empty one | [`0037`](../decisions/0037-an-unreadable-dacl-says-so.md) |
| never requests or stores the audit portion of a descriptor | [`0036`](../decisions/0036-capture-never-requests-the-sacl.md) |
| stores an exclusion's reason, names and time in the bundle | [`0062`](../decisions/0062-what-an-exclusion-attestation-asks-for.md) |

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
| be certain a finished run leaves evidence, a seal and an annotations file | `BundleWriterTests.AFinishedRunLeavesEvidenceASealAndAnAnnotationsFile` |  |
| be certain an interrupted run leaves nothing a reader can open | `BundleWriterTests.AnInterruptedRunLeavesNothingAReaderCanOpen` |  |
| be certain a bundle is never written over | `BundleWriterTests.ABundleIsNeverWrittenOver` |  |
| be certain nothing can be added after a bundle is sealed | `BundleWriterTests.NothingCanBeAddedAfterTheBundleIsSealed` |  |
| confirm a finished bundle verifies intact | `BundleWriterTests.AFinishedBundleVerifiesIntact` |  |
| be certain editing the evidence is reported as a mismatch | `BundleWriterTests.EditingTheEvidenceIsAMismatch` |  |
| tell an unreadable seal from an absent one | `BundleWriterTests.AnUnreadableSealIsNotReportedAsAnAbsentOne` |  |
| tell a descriptor that could not be parsed from an object that grants nothing | `BundleWriterTests.ADescriptorThatCouldNotBeParsedIsDistinguishableFromAnObjectThatGrantsNothing` |  |
| be certain the DACL state is stored rather than inferred from an empty entry list | `BundleWriterTests.TheDaclStateIsStoredRatherThanInferredFromAnEmptyEntryList` |  |
| find non-canonical descriptors without reading every entry | `BundleWriterTests.NonCanonicalDescriptorsCanBeFoundWithoutReadingEveryEntry` |  |
| find entries this product does not model, rather than losing them | `BundleWriterTests.EntriesThisProductDoesNotModelCanBeFoundByQueryingAceType` |  |
| tell an attribute that did not come back from one that has no values | `BundleWriterTests.AnAttributeWithNoValuesIsStoredTheSameWayAsOneThatDidNotComeBack` |  |
| be certain the writer refuses an attribute the catalogue does not name | `BundleWriterTests.TheWriterRefusesAnAttributeTheCatalogueDoesNotName` |  |
| be certain a descriptor belonging to a different object is refused | `BundleWriterTests.ADescriptorBelongingToADifferentObjectIsRefused` |  |
| see which partitions a run declined to read, stated in the evidence | `BundleWriterTests.APartitionTheRunDeclinedToReadIsStatedInTheEvidence` |  |
| find an object by an identity that survives a rename or a move | `BundleWriterTests.AnObjectIsStoredWithTheIdentityThatSurvivesARenameOrMove` |  |
| see the connection security a partition was read over | `BundleWriterTests.TheConnectionSecurityAPartitionWasReadOverIsRecorded` |  |
| be certain a container nobody captured is recorded as an unresolved reference | `BundleWriterTests.AContainerThatWasNeverCapturedIsRecordedAsAnUnresolvedReference` |  |
| be certain every catalogue attribute is stored somewhere | `BundleSchemaTests.EveryCatalogueAttributeIsStoredSomewhere` |  |
| be certain no two catalogue attributes collide on a column name | `BundleSchemaTests.NoTwoCatalogueAttributesShareAColumnName` |  |
| know an object read over an unencrypted connection may be missing confidential values | `EvidenceObjectTests.AnObjectReadOverAnUnencryptedConnectionMayBeMissingConfidentialValues` |  |
| tell one forest's runs from another's by their profile | `ProfileIdTests.TwoForestsProduceDifferentProfiles` |  |
| see the forest name kept beside the profile, so what was hashed is visible | `ProfileIdTests.TheForestNameIsKeptSoAReaderCanSeeWhatWasHashed` |  |
| open a sealed bundle and read what the run captured | `BundleReaderTests.ASealedBundleOpens` |  |
| be certain an interrupted run's bundle cannot be opened | `BundleReaderTests.AnInterruptedRunHasNothingToOpen` |  |
| be certain edited evidence is refused rather than read | `BundleReaderTests.EditedEvidenceIsNotOpened` |  |
| tell a damaged seal from an absent one when a bundle is refused | `BundleReaderTests.ADamagedSealIsRefusedAsUnreadable` |  |
| see which bundle a refusal was about | `BundleReaderTests.ARefusalNamesTheBundleItWasAbout` |  |
| learn from a bundle whether the run reached everything it declared | `BundleReaderTests.ASealedBundleThatReachedNoDomainStillOpensAndSaysSo` |  |
| be certain reading a bundle leaves it intact | `BundleReaderTests.OpeningABundleLeavesItStillIntact` |  |
| be certain reading a bundle writes nothing beside it | `BundleReaderTests.OpeningABundleWritesNoJournalBesideIt` |  |

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This section is the owner's to write.** What follows is a draft list of candidates, offered so
there is something to react to. It is not authoritative and nothing here has been decided.

- **Whether the acceptances sidecar carries an integrity check of its own.**
  [`0067`](../decisions/0067-an-acceptance-names-one-finding.md) decides acceptances sit beside the
  evidence and never inside it; the file and its name are drawn in code as
  `BundleLayout.AnnotationsFileName` and held by
  `BundleWriterTests.AFinishedRunLeavesEvidenceASealAndAnAnnotationsFile`. What is undrawn is its
  integrity: `evidence.db` carries a seal that detects corruption and the sidecar carries nothing,
  so damage to an acceptance history nobody can re-derive would be silent.
- **How large a bundle is allowed to get**, and what the product does when a forest does not fit.
- **Whether a bundle is ever pruned or aged out**, or kept for ever.
- **What a customer may do with a bundle** — whether it is meant to be opened by anything but this
  product.

---

## Open findings

| | | |
|---|---|---|
| — | none recorded for this area yet | — |
