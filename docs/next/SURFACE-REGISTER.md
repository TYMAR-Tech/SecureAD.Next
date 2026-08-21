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
| Result | SecureAD.Kernel | [how-failures-are-reported](../areas/how-failures-are-reported.md) |
| AuditError | SecureAD.Kernel | [how-failures-are-reported](../areas/how-failures-are-reported.md) |
| ErrorCategory | SecureAD.Kernel | [how-failures-are-reported](../areas/how-failures-are-reported.md) |
| ErrorSeverity | SecureAD.Kernel | [how-failures-are-reported](../areas/how-failures-are-reported.md) |
| SecurityDescriptorParser | SecureAD.Kernel | [what-we-capture](../areas/what-we-capture.md) |
| ParsedSecurityDescriptor | SecureAD.Kernel | [what-we-capture](../areas/what-we-capture.md) |
| ParsedAce | SecureAD.Kernel | [what-we-capture](../areas/what-we-capture.md) |
| AceType | SecureAD.Kernel | [what-we-capture](../areas/what-we-capture.md) |
| DaclState | SecureAD.Kernel | [what-we-capture](../areas/what-we-capture.md) |
| DaclCompleteness | SecureAD.Kernel | [what-we-capture](../areas/what-we-capture.md) |
| GenericRightsExpander | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| AceNormalizer | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| AceNormalizationResult | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| CanonicalAce | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| AceCanonicalization | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| DnHelper | SecureAD.Kernel | [who-is-who](../areas/who-is-who.md) |
| SchemaGuidCatalog | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| SchemaGuidEntry | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| SchemaGuidKind | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| SchemaGuidSource | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| DangerousPermissionClassifier | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| PermissionAssessment | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| PermissionVerdict | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| EntryReach | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| EntryReachReader | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
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
| SysvolCoverage | SecureAD.Evidence | [what-the-run-covered](../areas/what-the-run-covered.md) |
| SysvolReadOutcome | SecureAD.Evidence | [what-the-run-covered](../areas/what-the-run-covered.md) |
| GpoCoverage | SecureAD.Evidence | [what-the-run-covered](../areas/what-the-run-covered.md) |
| GpoReadOutcome | SecureAD.Evidence | [what-the-run-covered](../areas/what-the-run-covered.md) |
| GpoSettingScope | SecureAD.Evidence | [group-policy](../areas/group-policy.md) |
| RestrictedGroupRelationship | SecureAD.Evidence | [group-policy](../areas/group-policy.md) |
| CapturedAttributeCatalog | SecureAD.Audit | [what-we-capture](../areas/what-we-capture.md) |
| CapturedAttribute | SecureAD.Audit | [what-we-capture](../areas/what-we-capture.md) |
| ForestTopology | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| ForestController | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| ForestSubnet | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| OperatorSite | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| ForestRoles | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| RoleHolder | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| PdcEmulatorKnowledge | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| DomainPdcEmulator | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| ControllerSelection | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| DomainSelection | SecureAD.Audit | [the-new-audit-wizard](../areas/the-new-audit-wizard.md) |
| ForestBootstrap | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| ForestEntry | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| ForestEntrySource | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| IMachineDomain | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| MachineDomain | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| MachineAddresses | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| ForestPlan | SecureAD.Audit | [the-new-audit-wizard](../areas/the-new-audit-wizard.md) |
| PlanPreview | SecureAD.Audit | [the-new-audit-wizard](../areas/the-new-audit-wizard.md) |
| AttributeCardinality | SecureAD.Audit | [what-we-capture](../areas/what-we-capture.md) |
| AttributeStorage | SecureAD.Audit | [what-we-capture](../areas/what-we-capture.md) |
| CaptureUnit | SecureAD.Audit | [what-we-capture](../areas/what-we-capture.md) |
| NamingContextKind | SecureAD.Evidence | [what-we-capture](../areas/what-we-capture.md) |
| CaptureSearchRequestFactory | SecureAD.Audit | [what-we-capture](../areas/what-we-capture.md) |
| ContinuationReferenceReconciliation | SecureAD.Audit | [what-we-capture](../areas/what-we-capture.md) |
| ServerLimits | SecureAD.Audit | [running-a-capture](../areas/running-a-capture.md) |
| ServerLimit | SecureAD.Audit | [running-a-capture](../areas/running-a-capture.md) |
| RetryPolicy | SecureAD.Audit | [running-a-capture](../areas/running-a-capture.md) |
| DirectoryFailure | SecureAD.Audit | [running-a-capture](../areas/running-a-capture.md) |
| FailureResponse | SecureAD.Audit | [running-a-capture](../areas/running-a-capture.md) |
| LdapEntryReader | SecureAD.Audit | [what-we-capture](../areas/what-we-capture.md) |
| AttributeValues | SecureAD.Audit | [what-we-capture](../areas/what-we-capture.md) |
| AttributeCompleteness | SecureAD.Audit | [what-we-capture](../areas/what-we-capture.md) |
| AttributeRange | SecureAD.Audit | [what-we-capture](../areas/what-we-capture.md) |
| IDirectoryChannel | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| IDirectoryChannelFactory | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| DirectoryPage | SecureAD.Audit | [what-we-capture](../areas/what-we-capture.md) |
| PageCompleteness | SecureAD.Audit | [what-we-capture](../areas/what-we-capture.md) |
| CapturePlan | SecureAD.Audit | [running-a-capture](../areas/running-a-capture.md) |
| PartitionCapture | SecureAD.Audit | [running-a-capture](../areas/running-a-capture.md) |
| BundleCaptureSink | SecureAD.Audit | [running-a-capture](../areas/running-a-capture.md) |
| CaptureRun | SecureAD.Audit | [running-a-capture](../areas/running-a-capture.md) |
| CaptureSession | SecureAD.Audit | [running-a-capture](../areas/running-a-capture.md) |
| CaptureRunResult | SecureAD.Audit | [running-a-capture](../areas/running-a-capture.md) |
| RunCompletion | SecureAD.Audit | [running-a-capture](../areas/running-a-capture.md) |
| ForestDiscovery | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| CapturedObject | SecureAD.Audit | [what-we-capture](../areas/what-we-capture.md) |
| ObjectCompleteness | SecureAD.Audit | [what-we-capture](../areas/what-we-capture.md) |
| ICapturedObjectSink | SecureAD.Audit | [what-we-capture](../areas/what-we-capture.md) |
| ConnectionSecurityLevel | SecureAD.Evidence | [which-controller-we-read](../areas/which-controller-we-read.md) |
| ConnectionSecurityRung | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| ConnectionSecurityLadder | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| ConnectionLadderWalk | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| UnprotectedConnectionAllowance | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| DirectoryCredential | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| DirectoryConnectionSettings | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| ConnectionSecurityLog | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| ControllerConnectionSecurity | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| Preflight | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| NamedControllerCheck | SecureAD.Audit | [the-new-audit-wizard](../areas/the-new-audit-wizard.md) |
| NamedControllerAnswer | SecureAD.Audit | [the-new-audit-wizard](../areas/the-new-audit-wizard.md) |
| PreflightReport | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| DomainPreflight | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| PreflightAnswer | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| PreflightFile | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| PreflightContents | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| PreflightDomainRecord | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| AceSetHash | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| PermissionWordingWriter | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| PermissionWording | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| PermissionRight | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| PermissionScopeWriter | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| PermissionScope | SecureAD.Kernel | [what-a-permission-means](../areas/what-a-permission-means.md) |
| Sid | SecureAD.Kernel | [who-is-who](../areas/who-is-who.md) |
| WellKnownSidCatalog | SecureAD.Kernel | [who-is-who](../areas/who-is-who.md) |
| WellKnownSid | SecureAD.Kernel | [who-is-who](../areas/who-is-who.md) |
| WellKnownSidRole | SecureAD.Kernel | [who-is-who](../areas/who-is-who.md) |
| DomainRelativeSid | SecureAD.Kernel | [who-is-who](../areas/who-is-who.md) |
| DomainRelativeScope | SecureAD.Kernel | [who-is-who](../areas/who-is-who.md) |
| UserAccountControlWording | SecureAD.Kernel | [what-we-capture](../areas/what-we-capture.md) |
| UserAccountControlFlag | SecureAD.Kernel | [what-we-capture](../areas/what-we-capture.md) |
| DirectoryTime | SecureAD.Kernel | [what-we-capture](../areas/what-we-capture.md) |
| DirectoryTimeWording | SecureAD.Kernel | [what-we-capture](../areas/what-we-capture.md) |
| DirectoryTimeFormat | SecureAD.Kernel | [what-we-capture](../areas/what-we-capture.md) |
| GroupTypeWording | SecureAD.Kernel | [who-is-who](../areas/who-is-who.md) |
| BundleLayout | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| BundleSchema | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| BundleWriter | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| BundleReader | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| BundleDescription | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| DirectoryTree | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| TreeNode | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| TreeNodeOrigin | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| TreeGap | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| TreeGapReason | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| ListingScope | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| ListedObject | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| ObjectPage | SecureAD.Evidence | [how-results-are-shown](../areas/how-results-are-shown.md) |
| ObjectPermissions | SecureAD.Evidence | [what-a-permission-means](../areas/what-a-permission-means.md) |
| PermissionEntry | SecureAD.Evidence | [what-a-permission-means](../areas/what-a-permission-means.md) |
| PermissionTrustee | SecureAD.Evidence | [what-a-permission-means](../areas/what-a-permission-means.md) |
| DescriptorAvailability | SecureAD.Evidence | [what-a-permission-means](../areas/what-a-permission-means.md) |
| ObjectAttributes | SecureAD.Evidence | [what-we-capture](../areas/what-we-capture.md) |
| ObjectAttribute | SecureAD.Evidence | [what-we-capture](../areas/what-we-capture.md) |
| AttributeValue | SecureAD.Evidence | [what-we-capture](../areas/what-we-capture.md) |
| BundleSealing | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| AttestedExclusion | SecureAD.Evidence | [the-new-audit-wizard](../areas/the-new-audit-wizard.md) |
| ExclusionKind | SecureAD.Evidence | [the-new-audit-wizard](../areas/the-new-audit-wizard.md) |
| BundleSealContents | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| SealState | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| SealVerdict | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| EvidenceObject | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| EvidenceCompleteness | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| EvidenceAttribute | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| EvidenceValue | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| ProfileId | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| CoverageId | SecureAD.Evidence | [what-the-run-covered](../areas/what-the-run-covered.md) |
| RunState | SecureAD.Evidence | [the-run-library](../areas/the-run-library.md) |
| RunStateNames | SecureAD.Evidence | [the-run-library](../areas/the-run-library.md) |
| RunStateObservation | SecureAD.Evidence | [the-run-library](../areas/the-run-library.md) |
| RunStateReader | SecureAD.Evidence | [the-run-library](../areas/the-run-library.md) |
| RunLibrary | SecureAD.Evidence | [the-run-library](../areas/the-run-library.md) |
| RunOutcome | SecureAD.Evidence | [how-failures-are-reported](../areas/how-failures-are-reported.md) |
| RunOutcomeContents | SecureAD.Evidence | [how-failures-are-reported](../areas/how-failures-are-reported.md) |
| RunOutcomeFile | SecureAD.Evidence | [how-failures-are-reported](../areas/how-failures-are-reported.md) |
| DomainReadOutcome | SecureAD.Evidence | [what-the-run-covered](../areas/what-the-run-covered.md) |
| DomainCoverage | SecureAD.Evidence | [what-the-run-covered](../areas/what-the-run-covered.md) |
| ForestPartitionReadOutcome | SecureAD.Evidence | [what-the-run-covered](../areas/what-the-run-covered.md) |
| ForestPartitionCoverage | SecureAD.Evidence | [what-the-run-covered](../areas/what-the-run-covered.md) |
| RunCoverage | SecureAD.Evidence | [what-the-run-covered](../areas/what-the-run-covered.md) |
| RunSummary | SecureAD.Evidence | [the-run-library](../areas/the-run-library.md) |
| RunListing | SecureAD.Evidence | [the-run-library](../areas/the-run-library.md) |
| RunMoment | SecureAD.Evidence | [the-run-library](../areas/the-run-library.md) |
| RunAnnotation | SecureAD.Evidence | [the-run-library](../areas/the-run-library.md) |
| RunAnnotations | SecureAD.Evidence | [the-run-library](../areas/the-run-library.md) |
| ComparabilityOutcome | SecureAD.Evidence | [how-compare-works](../areas/how-compare-works.md) |
| DriftCardShape | SecureAD.Evidence | [how-compare-works](../areas/how-compare-works.md) |
| ComparabilityVerdict | SecureAD.Evidence | [how-compare-works](../areas/how-compare-works.md) |
| BaselineVerdict | SecureAD.Evidence | [how-compare-works](../areas/how-compare-works.md) |
| RunComparability | SecureAD.Evidence | [how-compare-works](../areas/how-compare-works.md) |
| StoredAttributeCompleteness | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| UnresolvedReferenceKind | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| UnresolvedReferenceReason | SecureAD.Evidence | [how-a-run-is-stored](../areas/how-a-run-is-stored.md) |
| PartitionCoverage | SecureAD.Evidence | [what-the-run-covered](../areas/what-the-run-covered.md) |
| LdapDirectoryChannel | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |
| LdapDirectoryChannelFactory | SecureAD.Audit | [which-controller-we-read](../areas/which-controller-we-read.md) |

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
[`S-4`](S-4-dangerous-permission-classification.md). Each was the same lesson: a library reading a
library does not answer the question *what can something that runs reach*, so an entry must not come
off on the strength of a consumer that is itself unreached.

**That lesson survives the change and is not enforced by this register.** Area ownership says where a
type belongs; it says nothing about whether anything reaches it. Gate 5b is still the only check
that would, and it is still outstanding. Recording the two separately is deliberate — a check that
quietly implies more coverage than it has is how the original wording of gate 5 came to pass against
a tree in which nothing was used at all.
