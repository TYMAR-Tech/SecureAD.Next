# Group Policy

**Area.** What the product reads about Group Policy: the objects in the directory, the files behind
them in SYSVOL, and what those files contain. Group Policy is where a permission on one object turns
into code running on many machines, which is why it is read at all.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| reads a policy's file permissions below the root folder, not only at it | [`0043`](../decisions/0043-a-gpos-file-permissions-are-read-below-the-root-folder.md) |
| records SYSVOL coverage beside the capture units, in the same terms | [`0044`](../decisions/0044-sysvol-coverage-is-recorded-beside-the-capture-units.md) |
| captures the policy container's own attributes as evidence | [`0065`](../decisions/0065-the-catalogue-recovers-what-the-rebuild-dropped.md) |
| holds the rule catalogue as data and the rule logic as code | [`0010`](../decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md) |
| treats an absent view as a degraded run, never as a negative answer | [`0002`](../decisions/0002-absent-view-means-degraded-run.md) |

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** A capability whose test does not exist, or does not pass, fails the build — so nothing
here can claim something the product does not do.

| An operator can… | Proven by |
|---|---|
| see which client-side extensions a policy declares | `GpoClientSideExtensionsTests.WhenSingleRegistryGroup_ThenReturnsRegistryCse` |
| be certain a malformed extension list is recorded rather than silently skipped | `GpoClientSideExtensionsTests.WhenMalformedTokens_ThenTheyAreRecordedRatherThanSkippedSilently` |
| be certain an absent extension list reports no errors, so an error always means something | `GpoClientSideExtensionsTests.WhenAttributeIsAbsent_ThenNoErrorsAreReported` |
| be certain duplicate extension entries are reduced to one | `GpoClientSideExtensionsTests.WhenDuplicateCseGroups_ThenDeduplicated` |
| have a policy's registry settings read from the file behind it | `RegistryPolicyParserTests.WhenDwordEntry_ThenKeyValueAndTypeParsed` |
| be certain a corrupt registry policy file reports an error rather than throwing | `RegistryPolicyParserTests.WhenInvalidSignature_ThenReturnsError` |
| be certain a policy file of an unexpected version is still parsed, and says so | `RegistryPolicyParserTests.WhenUnexpectedVersion_ThenReturnsErrorButStillParses` |
| have a security template read whatever encoding it was written in | `SecurityTemplateParserTests.WhenUtf16LeWithBom_ThenParsesSections` |
| see which principals a policy grants a privilege to | `SecurityTemplateParserTests.WhenPrivilegeRights_ThenTrusteesSplitAndStarStripped` |
| be certain a missing template section is empty rather than an error | `SecurityTemplateParserTests.WhenSectionAbsent_ThenGetSectionReturnsEmpty` |
| be certain the raw settings of a template are preserved rather than interpreted away | `SecurityTemplateParserTests.WhenSystemAccessSection_ThenRawSettingsPreserved` |
| find a password stored in a Group Policy preference | `GroupPolicyPreferenceParserTests.WhenCpasswordPresent_ThenValueNeverAppearsInResult` |
| be certain that finding never carries the password itself | `GroupPolicyPreferenceParserTests.WhenFindingType_ThenHasNoPasswordProperty` |
| be certain one finding is raised per affected account | `GroupPolicyPreferenceParserTests.WhenMultipleUsersWithCpassword_ThenOneFindingEach` |
| be certain a hostile preference file cannot make the product fetch anything | `GroupPolicyPreferenceParserTests.WhenDtdExternalEntity_ThenParsesWithoutResolvingEntity` |
| be certain malformed policy XML returns an error rather than throwing | `GroupPolicyPreferenceParserTests.WhenMalformedXml_ThenReturnsErrorNotThrow` |

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This section is the owner's to write.** What follows is a draft list of candidates, offered so
there is something to react to. It is not authoritative and nothing here has been decided.

- **What the product judges about a policy, as opposed to what it reads.** The parsers exist; the
  rules that read them are largely unwritten, and which questions matter has not been settled.
- **Whether a policy's effect is worked out** — which objects it actually reaches through links,
  blocked inheritance, enforcement and security filtering — or whether the product reports the link
  and stops.
- **How a policy that is linked but disabled is treated.**
- **Whether SYSVOL file permissions are judged as permissions**, on the same footing as directory
  permissions, or reported separately.
- **What happens when the directory and SYSVOL disagree** — a policy container with no folder, or a
  folder with no container.

---

## Open findings

| | | |
|---|---|---|
| — | none recorded for this area yet | — |

---

## Reference — the old application

**Reference only. Nothing here is owed, and a row existing here does not mean it is being built.**

The predecessor had a `GpoRuleEvaluator` among its eleven rule evaluators. Its rows in the reference
inventory describe that evaluator, not this product's.
