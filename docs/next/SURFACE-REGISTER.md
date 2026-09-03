# Surface register

Every public type in the rebuild, and what is expected to use it.

A **public type** is a piece of the product that other parts are allowed to use — as opposed to
internal workings that only its own component can see. Public surface is the part that outlives its
author: once something is public, anything may come to depend on it, and it stops being cheap to
remove.

## What this is for

The old product carries six screens no user can reach and twenty-eight buttons wired to nothing.
Each was built for a reason. Each stopped being connected. Nobody noticed, because nothing was
watching.

For an audit tool that matters more than it would elsewhere. A screen that looks like it reports on
something, and reports nothing, is worse than a missing screen — a customer makes a security
decision on the strength of it.

This register is the watching. Every public type is listed, and every one names the **area** it
belongs to, so a type serving no part of the product cannot sit here unnoticed. A type belonging to
no area is either dead surface or a capability nobody wrote down — and the second is what produced
the old application's six unreachable grids.

## What it does not do

**This register cannot tell you a type is genuinely used.** It checks the paperwork: that every
public type is accounted for, and that the area it names is a real area file.

Proving a type is actually reached by running code is gate 5b, and it needs something that runs to
trace from. See [`README.md`](README.md) § Gates for where that stands. *This paragraph previously
stated that `next/` has no entry point, which stopped being true when the shell shipped. Corrected
2026-08-16; the claim is recorded in `S-43` as one
of the contradictions that session was called to end.*

The two are recorded separately on purpose. A check that quietly implies more coverage than it has
is how the original single wording of gate 5 came to pass against a tree in which nothing was used
at all.

## The register

`Area` names the area file that owns the type — the page a session reads before working on it. It is
a statement about where a type belongs, not a forecast about who will use it, which is what this
column held until 2026-08-16. Moving the binding off the inventory is what frees the inventory to stop
being a plan.

**A type belongs to exactly one area.** Two areas claiming one type leaves two pages responsible for
it and a reader unable to tell which owns it; no area claiming it is surface nobody owns.

**Seven of the nineteen areas own no type here, and that is expected rather than a gap.** Six of them
have nothing built at all — the judgement and reporting half of the product — and one,
[how the app looks](../areas/how-the-app-looks.md), owns the shell, which this register does not
cover. The register reads `SecureAD.Kernel`, `SecureAD.Evidence` and `SecureAD.Audit`; the shell's
surface is held by `ShellSurfaceGateTests` instead.

The table below sits between the two markers around it, so the test parses only the rows.

<!-- REGISTER:BEGIN -->

| Type | Project | Area |
|---|---|---|
| Result | SecureAD.Kernel | [how-failure-is-reported](../layers/kernel/how-failure-is-reported.md) |
| AuditError | SecureAD.Kernel | [how-failure-is-reported](../layers/kernel/how-failure-is-reported.md) |
| ErrorCategory | SecureAD.Kernel | [how-failure-is-reported](../layers/kernel/how-failure-is-reported.md) |
| ErrorSeverity | SecureAD.Kernel | [how-failure-is-reported](../layers/kernel/how-failure-is-reported.md) |
| IRunLog | SecureAD.Kernel | [how-failure-is-reported](../layers/kernel/how-failure-is-reported.md) |
| RunLog | SecureAD.Kernel | [how-failure-is-reported](../layers/kernel/how-failure-is-reported.md) |
| RunLogDetail | SecureAD.Kernel | [how-failure-is-reported](../layers/kernel/how-failure-is-reported.md) |
| SecurityDescriptorParser | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| ParsedSecurityDescriptor | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| ParsedAce | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| AceType | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| DaclState | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| DaclCompleteness | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| GenericRightsExpander | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| AceNormalizer | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| AceNormalizationResult | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| CanonicalAce | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| AceCanonicalization | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| DnHelper | SecureAD.Kernel | [distinguished-names](../layers/kernel/distinguished-names.md) |
| SchemaGuidCatalog | SecureAD.Kernel | [what-a-schema-guid-means](../layers/schema/what-a-schema-guid-means.md) |
| SchemaGuidEntry | SecureAD.Kernel | [what-a-schema-guid-means](../layers/schema/what-a-schema-guid-means.md) |
| SchemaGuidKind | SecureAD.Kernel | [what-a-schema-guid-means](../layers/schema/what-a-schema-guid-means.md) |
| SchemaGuidSource | SecureAD.Kernel | [what-a-schema-guid-means](../layers/schema/what-a-schema-guid-means.md) |
| DangerousPermissionClassifier | SecureAD.Kernel | [permission-classification](../layers/kernel/permission-classification.md) |
| PermissionAssessment | SecureAD.Kernel | [permission-classification](../layers/kernel/permission-classification.md) |
| PermissionVerdict | SecureAD.Kernel | [permission-classification](../layers/kernel/permission-classification.md) |
| EntryReach | SecureAD.Kernel | [permission-classification](../layers/kernel/permission-classification.md) |
| EntryReachReader | SecureAD.Kernel | [permission-classification](../layers/kernel/permission-classification.md) |
| RegistryPolicyParser | SecureAD.Kernel | [group-policy](../areas/group-policy.md) |
| ParsedRegistryPolicy | SecureAD.Kernel | [group-policy](../areas/group-policy.md) |
| RegistryPolicyEntry | SecureAD.Kernel | [group-policy](../areas/group-policy.md) |
| RegistryValueType | SecureAD.Kernel | [group-policy](../areas/group-policy.md) |
| SecurityTemplateParser | SecureAD.Kernel | [group-policy](../areas/group-policy.md) |
| ParsedSecurityTemplate | SecureAD.Kernel | [group-policy](../areas/group-policy.md) |
| SecurityTemplateSetting | SecureAD.Kernel | [group-policy](../areas/group-policy.md) |
| RestrictedGroup | SecureAD.Kernel | [group-policy](../areas/group-policy.md) |
| GroupPolicyPreferenceParser | SecureAD.Kernel | [group-policy](../areas/group-policy.md) |
| PolicyLinkList | SecureAD.Kernel | [group-policy](../areas/group-policy.md) |
| PolicyLink | SecureAD.Kernel | [group-policy](../areas/group-policy.md) |
| ParsedGppFile | SecureAD.Kernel | [group-policy](../areas/group-policy.md) |
| GppPasswordFinding | SecureAD.Kernel | [group-policy](../areas/group-policy.md) |
| GpoClientSideExtensions | SecureAD.Kernel | [group-policy](../areas/group-policy.md) |
| ParsedCseList | SecureAD.Kernel | [group-policy](../areas/group-policy.md) |
| GpoClientSideExtensionCatalog | SecureAD.Kernel | [group-policy](../areas/group-policy.md) |
| ISysvolFileReader | SecureAD.Audit | [group-policy](../areas/group-policy.md) |
| SmbSysvolFileReader | SecureAD.Audit | [group-policy](../areas/group-policy.md) |
| GpoTarget | SecureAD.Audit | [group-policy](../areas/group-policy.md) |
| GpoInventory | SecureAD.Audit | [group-policy](../areas/group-policy.md) |
| SysvolCapture | SecureAD.Audit | [group-policy](../areas/group-policy.md) |
| SysvolCoverage | SecureAD.Evidence | [run-identity-and-coverage](../layers/evidence/run-identity-and-coverage.md) |
| SysvolReadOutcome | SecureAD.Evidence | [run-identity-and-coverage](../layers/evidence/run-identity-and-coverage.md) |
| GpoCoverage | SecureAD.Evidence | [run-identity-and-coverage](../layers/evidence/run-identity-and-coverage.md) |
| GpoReadOutcome | SecureAD.Evidence | [run-identity-and-coverage](../layers/evidence/run-identity-and-coverage.md) |
| GpoSettingScope | SecureAD.Evidence | [group-policy](../areas/group-policy.md) |
| RestrictedGroupRelationship | SecureAD.Evidence | [group-policy](../areas/group-policy.md) |
| CapturedAttributeCatalog | SecureAD.Audit | [the-attribute-catalogue](../layers/audit/the-attribute-catalogue.md) |
| CapturedAttribute | SecureAD.Audit | [the-attribute-catalogue](../layers/audit/the-attribute-catalogue.md) |
| ForestTopology | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| ForestController | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| ForestSubnet | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| OperatorSite | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| ForestRoles | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| RoleHolder | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| PdcEmulatorKnowledge | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| DomainPdcEmulator | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| ControllerSelection | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| DomainSelection | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| ForestBootstrap | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| ForestEntry | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| ForestEntrySource | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| IMachineDomain | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| MachineDomain | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| MachineAddresses | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| ForestPlan | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| PlanPreview | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| AttributeCardinality | SecureAD.Audit | [the-attribute-catalogue](../layers/audit/the-attribute-catalogue.md) |
| AttributeStorage | SecureAD.Audit | [the-attribute-catalogue](../layers/audit/the-attribute-catalogue.md) |
| CaptureUnit | SecureAD.Audit | [the-search-capture-issues](../layers/audit/the-search-capture-issues.md) |
| NamingContextKind | SecureAD.Evidence | [run-identity-and-coverage](../layers/evidence/run-identity-and-coverage.md) |
| CaptureSearchRequestFactory | SecureAD.Audit | [the-search-capture-issues](../layers/audit/the-search-capture-issues.md) |
| ContinuationReferenceReconciliation | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| ServerLimits | SecureAD.Audit | [limits-and-failures](../layers/audit/limits-and-failures.md) |
| ServerLimit | SecureAD.Audit | [limits-and-failures](../layers/audit/limits-and-failures.md) |
| RetryPolicy | SecureAD.Audit | [limits-and-failures](../layers/audit/limits-and-failures.md) |
| DirectoryFailure | SecureAD.Audit | [limits-and-failures](../layers/audit/limits-and-failures.md) |
| FailureResponse | SecureAD.Audit | [limits-and-failures](../layers/audit/limits-and-failures.md) |
| LdapEntryReader | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| AttributeValues | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| AttributeCompleteness | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| AttributeRange | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| IDirectoryChannel | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| IDirectoryChannelFactory | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| DirectoryPage | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| PageCompleteness | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| CapturePlan | SecureAD.Audit | [the-search-capture-issues](../layers/audit/the-search-capture-issues.md) |
| PartitionCapture | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| BundleCaptureSink | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| CaptureRun | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| CaptureSession | SecureAD.Audit | [what-preflight-proves](../layers/connect/what-preflight-proves.md) |
| CaptureRunResult | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| RunCompletion | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| ForestDiscovery | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |
| CapturedObject | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| ObjectCompleteness | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| ICapturedObjectSink | SecureAD.Audit | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| ConnectionSecurityLevel | SecureAD.Evidence | [the-connection-ladder](../layers/connect/the-connection-ladder.md) |
| ConnectionSecurityRung | SecureAD.Audit | [the-connection-ladder](../layers/connect/the-connection-ladder.md) |
| ConnectionSecurityLadder | SecureAD.Audit | [the-connection-ladder](../layers/connect/the-connection-ladder.md) |
| ConnectionLadderWalk | SecureAD.Audit | [the-connection-ladder](../layers/connect/the-connection-ladder.md) |
| UnprotectedConnectionAllowance | SecureAD.Audit | [the-connection-ladder](../layers/connect/the-connection-ladder.md) |
| DirectoryCredential | SecureAD.Audit | [how-a-connection-is-opened](../layers/connect/how-a-connection-is-opened.md) |
| DirectoryConnectionSettings | SecureAD.Audit | [how-a-connection-is-opened](../layers/connect/how-a-connection-is-opened.md) |
| ConnectionSecurityLog | SecureAD.Audit | [the-connection-ladder](../layers/connect/the-connection-ladder.md) |
| ControllerConnectionSecurity | SecureAD.Audit | [the-connection-ladder](../layers/connect/the-connection-ladder.md) |
| Preflight | SecureAD.Audit | [what-preflight-proves](../layers/connect/what-preflight-proves.md) |
| NamedControllerCheck | SecureAD.Audit | [what-preflight-proves](../layers/connect/what-preflight-proves.md) |
| NamedControllerAnswer | SecureAD.Audit | [what-preflight-proves](../layers/connect/what-preflight-proves.md) |
| PreflightReport | SecureAD.Audit | [what-preflight-proves](../layers/connect/what-preflight-proves.md) |
| DomainPreflight | SecureAD.Audit | [what-preflight-proves](../layers/connect/what-preflight-proves.md) |
| PreflightAnswer | SecureAD.Audit | [what-preflight-proves](../layers/connect/what-preflight-proves.md) |
| PreflightFile | SecureAD.Audit | [what-preflight-proves](../layers/connect/what-preflight-proves.md) |
| PreflightContents | SecureAD.Audit | [what-preflight-proves](../layers/connect/what-preflight-proves.md) |
| PreflightDomainRecord | SecureAD.Audit | [what-preflight-proves](../layers/connect/what-preflight-proves.md) |
| AceSetHash | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| PermissionWordingWriter | SecureAD.Kernel | [naming](../layers/kernel/naming.md) |
| PermissionWording | SecureAD.Kernel | [naming](../layers/kernel/naming.md) |
| PermissionRight | SecureAD.Kernel | [naming](../layers/kernel/naming.md) |
| PermissionScopeWriter | SecureAD.Kernel | [permission-classification](../layers/kernel/permission-classification.md) |
| PermissionScope | SecureAD.Kernel | [permission-classification](../layers/kernel/permission-classification.md) |
| Sid | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| WellKnownSidCatalog | SecureAD.Kernel | [naming](../layers/kernel/naming.md) |
| WellKnownSid | SecureAD.Kernel | [naming](../layers/kernel/naming.md) |
| WellKnownSidRole | SecureAD.Kernel | [naming](../layers/kernel/naming.md) |
| DomainRelativeSid | SecureAD.Kernel | [naming](../layers/kernel/naming.md) |
| DomainRelativeScope | SecureAD.Kernel | [naming](../layers/kernel/naming.md) |
| UserAccountControlWording | SecureAD.Kernel | [naming](../layers/kernel/naming.md) |
| UserAccountControlFlag | SecureAD.Kernel | [naming](../layers/kernel/naming.md) |
| DirectoryTime | SecureAD.Kernel | [naming](../layers/kernel/naming.md) |
| DirectoryTimeWording | SecureAD.Kernel | [naming](../layers/kernel/naming.md) |
| DirectoryTimeFormat | SecureAD.Kernel | [naming](../layers/kernel/naming.md) |
| GroupTypeWording | SecureAD.Kernel | [naming](../layers/kernel/naming.md) |
| BundleLayout | SecureAD.Evidence | [the-bundle-on-disk](../layers/evidence/the-bundle-on-disk.md) |
| AnalysisStoreKind | SecureAD.Evidence | [the-bundle-on-disk](../layers/evidence/the-bundle-on-disk.md) |
| AnalysisStoreGeneration | SecureAD.Evidence | [the-bundle-on-disk](../layers/evidence/the-bundle-on-disk.md) |
| AnalysisStoreLifecycle | SecureAD.Evidence | [the-bundle-on-disk](../layers/evidence/the-bundle-on-disk.md) |
| RunLogFile | SecureAD.Evidence | [the-bundle-on-disk](../layers/evidence/the-bundle-on-disk.md) |
| BundleSchema | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| BundleWriter | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| BundleObjects | SecureAD.Evidence | [what-an-object-holds](../layers/evidence/what-an-object-holds.md) |
| BundleReader | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| BundleDescription | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| ContinuationReconciliation | SecureAD.Evidence | [what-a-bundle-holds](../layers/evidence/what-a-bundle-holds.md) |
| ContinuationReconciliationOutcome | SecureAD.Evidence | [what-a-bundle-holds](../layers/evidence/what-a-bundle-holds.md) |
| DirectoryTree | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| TreeNode | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| TreeNodeOrigin | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| TreeGap | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| TreeGapReason | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| ListingScope | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| ListedObject | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| ObjectPage | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| ObjectPermissions | SecureAD.Evidence | [what-an-objects-permissions-hold](../layers/evidence/what-an-objects-permissions-hold.md) |
| PermissionEntry | SecureAD.Evidence | [what-an-objects-permissions-hold](../layers/evidence/what-an-objects-permissions-hold.md) |
| PermissionTrustee | SecureAD.Evidence | [what-an-objects-permissions-hold](../layers/evidence/what-an-objects-permissions-hold.md) |
| DescriptorAvailability | SecureAD.Evidence | [what-an-objects-permissions-hold](../layers/evidence/what-an-objects-permissions-hold.md) |
| ObjectAttributes | SecureAD.Evidence | [what-an-object-holds](../layers/evidence/what-an-object-holds.md) |
| ObjectAttribute | SecureAD.Evidence | [what-an-object-holds](../layers/evidence/what-an-object-holds.md) |
| AttributeValue | SecureAD.Evidence | [what-an-object-holds](../layers/evidence/what-an-object-holds.md) |
| BundleSealing | SecureAD.Evidence | [the-bundle-on-disk](../layers/evidence/the-bundle-on-disk.md) |
| AttestedExclusion | SecureAD.Evidence | [a-domain-left-out-on-purpose](../layers/evidence/a-domain-left-out-on-purpose.md) |
| ExclusionKind | SecureAD.Evidence | [a-domain-left-out-on-purpose](../layers/evidence/a-domain-left-out-on-purpose.md) |
| BundleSealContents | SecureAD.Evidence | [the-bundle-on-disk](../layers/evidence/the-bundle-on-disk.md) |
| SealState | SecureAD.Evidence | [the-bundle-on-disk](../layers/evidence/the-bundle-on-disk.md) |
| SealVerdict | SecureAD.Evidence | [the-bundle-on-disk](../layers/evidence/the-bundle-on-disk.md) |
| EvidenceObject | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| EvidenceCompleteness | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| EvidenceAttribute | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| EvidenceValue | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| ProfileId | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| CoverageId | SecureAD.Evidence | [run-identity-and-coverage](../layers/evidence/run-identity-and-coverage.md) |
| RunState | SecureAD.Evidence | [how-a-bundle-is-read](../layers/evidence/how-a-bundle-is-read.md) |
| RunStateNames | SecureAD.Evidence | [how-a-bundle-is-read](../layers/evidence/how-a-bundle-is-read.md) |
| RunStateObservation | SecureAD.Evidence | [the-bundle-on-disk](../layers/evidence/the-bundle-on-disk.md) |
| RunStateReader | SecureAD.Evidence | [the-bundle-on-disk](../layers/evidence/the-bundle-on-disk.md) |
| RunLibrary | SecureAD.Evidence | [how-a-bundle-is-read](../layers/evidence/how-a-bundle-is-read.md) |
| RunOutcome | SecureAD.Evidence | [the-bundle-on-disk](../layers/evidence/the-bundle-on-disk.md) |
| RunOutcomeContents | SecureAD.Evidence | [the-bundle-on-disk](../layers/evidence/the-bundle-on-disk.md) |
| RunOutcomeFile | SecureAD.Evidence | [the-bundle-on-disk](../layers/evidence/the-bundle-on-disk.md) |
| DomainReadOutcome | SecureAD.Evidence | [run-identity-and-coverage](../layers/evidence/run-identity-and-coverage.md) |
| DomainCoverage | SecureAD.Evidence | [run-identity-and-coverage](../layers/evidence/run-identity-and-coverage.md) |
| ForestPartitionReadOutcome | SecureAD.Evidence | [run-identity-and-coverage](../layers/evidence/run-identity-and-coverage.md) |
| ForestPartitionCoverage | SecureAD.Evidence | [run-identity-and-coverage](../layers/evidence/run-identity-and-coverage.md) |
| RunCoverage | SecureAD.Evidence | [run-identity-and-coverage](../layers/evidence/run-identity-and-coverage.md) |
| RunScope | SecureAD.Evidence | [how-a-bundle-is-read](../layers/evidence/how-a-bundle-is-read.md) |
| RunSummary | SecureAD.Evidence | [whether-two-runs-compare](../layers/evidence/whether-two-runs-compare.md) |
| RunListing | SecureAD.Evidence | [how-a-bundle-is-read](../layers/evidence/how-a-bundle-is-read.md) |
| RunMoment | SecureAD.Evidence | [how-a-bundle-is-read](../layers/evidence/how-a-bundle-is-read.md) |
| RunAnnotation | SecureAD.Evidence | [what-an-operator-writes-on-a-run](../layers/evidence/what-an-operator-writes-on-a-run.md) |
| RunAnnotations | SecureAD.Evidence | [what-an-operator-writes-on-a-run](../layers/evidence/what-an-operator-writes-on-a-run.md) |
| ComparabilityOutcome | SecureAD.Evidence | [whether-two-runs-compare](../layers/evidence/whether-two-runs-compare.md) |
| DriftCardShape | SecureAD.Evidence | [whether-two-runs-compare](../layers/evidence/whether-two-runs-compare.md) |
| ComparabilityVerdict | SecureAD.Evidence | [whether-two-runs-compare](../layers/evidence/whether-two-runs-compare.md) |
| BaselineVerdict | SecureAD.Evidence | [whether-two-runs-compare](../layers/evidence/whether-two-runs-compare.md) |
| RunComparability | SecureAD.Evidence | [whether-two-runs-compare](../layers/evidence/whether-two-runs-compare.md) |
| StoredAttributeCompleteness | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| UnresolvedReferenceKind | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| UnresolvedReferenceReason | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| PartitionCoverage | SecureAD.Evidence | [how-a-controller-is-read](../layers/audit/how-a-controller-is-read.md) |
| LdapDirectoryChannel | SecureAD.Audit | [how-a-connection-is-opened](../layers/connect/how-a-connection-is-opened.md) |
| LdapDirectoryChannelFactory | SecureAD.Audit | [how-a-connection-is-opened](../layers/connect/how-a-connection-is-opened.md) |
| DomainControllerSignals | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| LapsCapability | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| LapsCapabilityKind | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| LapsCapabilityBasis | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| LapsPlatformCatalog | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| AttributeReading | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| JudgementRunState | SecureAD.Judgement | [the-judgement-store](../layers/judgement/the-judgement-store.md) |
| JudgementDescription | SecureAD.Judgement | [the-judgement-store](../layers/judgement/the-judgement-store.md) |
| JudgementReader | SecureAD.Judgement | [the-judgement-store](../layers/judgement/the-judgement-store.md) |
| StoredJudgement | SecureAD.Judgement | [the-judgement-store](../layers/judgement/the-judgement-store.md) |
| StoredRuleExecution | SecureAD.Judgement | [the-judgement-store](../layers/judgement/the-judgement-store.md) |
| StoredRuleExecutions | SecureAD.Judgement | [the-judgement-store](../layers/judgement/the-judgement-store.md) |
| JudgingRun | SecureAD.Judgement | [the-judgement-store](../layers/judgement/the-judgement-store.md) |
| JudgementSchema | SecureAD.Judgement | [the-judgement-store](../layers/judgement/the-judgement-store.md) |
| JudgementWriter | SecureAD.Judgement | [the-judgement-store](../layers/judgement/the-judgement-store.md) |
| MissingInput | SecureAD.Judgement | [the-judgement-store](../layers/judgement/the-judgement-store.md) |
| FindingsQuery | SecureAD.Judgement | [the-judgement-store](../layers/judgement/the-judgement-store.md) |
| FindingsPage | SecureAD.Judgement | [the-judgement-store](../layers/judgement/the-judgement-store.md) |
| FindingsPageMark | SecureAD.Judgement | [the-judgement-store](../layers/judgement/the-judgement-store.md) |
| FindingsFilterValues | SecureAD.Judgement | [the-judgement-store](../layers/judgement/the-judgement-store.md) |
| RuleExecution | SecureAD.Judgement | [the-judgement-store](../layers/judgement/the-judgement-store.md) |
| RuleExecutionOutcome | SecureAD.Judgement | [the-judgement-store](../layers/judgement/the-judgement-store.md) |
| Finding | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| FindingEvidence | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| FindingSubject | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| FindingSubjectKind | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| DerivedFactKind | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| JudgingContext | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| AdminCountWithoutProtection | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| AdminCountWithoutProtectionEvidence | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| NoKerberosPreauthentication | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| UserAccountControlEvidence | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| PrivilegedSidHistory | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| PasswordNotRequired | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| ReversiblePasswordEncryption | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| DesEncryptionOnly | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| KerberoastablePrivilegedAccount | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| KerberoastableAccountEvidence | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| TextReading | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| PrivilegedSidCatalogue | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| PrivilegedSidHistoryEvidence | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| PrivilegedSidHistoryMatch | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| SidReading | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| IRule | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| RuleCatalogue | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| RuleDefinition | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| RuleGuidance | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| RuleGuidanceCatalogue | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| RuleVerdict | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| UnresolvedInput | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| UnresolvedReason | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| Severity | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| UnconstrainedDelegationEvidence | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| UnconstrainedDelegationOnAccount | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| UnconstrainedDelegationOnNonDomainController | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| StoredFindings | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| EvaluatedRule | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| Stage2aRun | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| DerivationProgress | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| DerivationRunState | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| DerivationPhaseOutcome | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| ExpansionBudget | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| ExpansionLimit | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| DerivationCompleteness | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| DerivationReader | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| StoredDerivation | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| DerivationDescription | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| StoredDerivationPhase | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| DerivationSize | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| ProtectedPrincipalEvaluation | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| ProtectionUnknownReason | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| ProtectedPrincipalBasisKind | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| ProtectedPrincipalBasis | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| ProtectedPrincipalProductAvailability | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| StoredAdminSdCatalogueEntry | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| StoredProtectedPrincipalFact | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| StoredProtectedPrincipalDerivation | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| StoredProtectedPrincipalProduct | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| AttributeVisibilityDeriver | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| AttributeVisibilityAnswer | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| AttributeVisibilityAvailability | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| AttributeVisibilityFact | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| StoredAttributeVisibility | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| StoredAttributeVisibilityProduct | SecureAD.Derivation | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| CapturedSchemaAttributeReader | SecureAD.Evidence | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| SchemaAttributeDefinition | SecureAD.Evidence | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| SchemaAttributeReading | SecureAD.Evidence | [what-stage-2a-derives](../layers/derivation/what-stage-2a-derives.md) |
| SchemaAttributeFlags | SecureAD.Kernel | [what-a-schema-guid-means](../layers/schema/what-a-schema-guid-means.md) |
| LapsMissingOnComputer | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| LapsRotationStale | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| WindowsLapsNotAppliedOnCapableComputer | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| LapsAttributes | SecureAD.Judgement | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| LapsDeploymentEvidence | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| LapsTimestampReading | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| LapsTimestamp | SecureAD.Evidence | [what-a-finding-is](../layers/judgement/what-a-finding-is.md) |
| LapsComputer | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| LapsManagement | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| LapsPage | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| DirectoryHeuristics | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| HeuristicCharacter | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| HeuristicReadOutcome | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| AdminSdExclusionMask | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |
| AdminSdExcludableGroup | SecureAD.Kernel | [security-descriptors](../layers/kernel/security-descriptors.md) |

<!-- REGISTER:END -->

## What changed on 2026-08-16

**This register used to forecast, and now it assigns.** Every row named an inventory row expected to
become the type's first production consumer, with a column explaining the basis. That made the
build depend on the inventory, which is the thing being demoted: an inventory of the predecessor is
reference material, and nothing should be obliged to keep it current.

The forecasts are not carried forward. They were a genuine device and they did real work — three
findings came out of them, recorded where they were found: `F-S13-3` in
`S-13`, `F-S7-42` in
`S-7`, and `F-S4-5` in
[permission classification](../layers/kernel/permission-classification.md). Each was the same lesson: a library reading a
library does not answer the question *what can something that runs reach*, so an entry must not come
off on the strength of a consumer that is itself unreached.

**That lesson survives the change and is not enforced by this register.** Area ownership says where a
type belongs; it says nothing about whether anything reaches it. Gate 5b is still the only check
that would, and it is still outstanding. Recording the two separately is deliberate — a check that
quietly implies more coverage than it has is how the original wording of gate 5 came to pass against
a tree in which nothing was used at all.
