# The judgement store

**Code:** `next/src/SecureAD.Judgement/`
**Layer:** Judgement — where what the rules concluded is kept, and why it is not kept with the evidence.

[`what-a-finding-is.md`](what-a-finding-is.md) says what a rule makes of an object. This page is
where that answer goes: a second database in the bundle's own directory, written after capture has
finished and sealed separately from the evidence it judged.

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `JudgementSchema` | Every table in a judgement store, and the indexes built once writing is done |
| `JudgingRun` | Judging a sealed bundle: read every object once, offer it to every rule, write what they concluded |
| `JudgementWriter` | The one way a judgement store gets written |
| `JudgementReader` | Reads a store back, and refuses one that does not belong to the bundle it sits in |
| `JudgementDescription` | What one judging recorded about itself |
| `StoredJudgement` | Everything a judging concluded: what it found, and which rules were run to produce it |
| `StoredRuleExecution` | One rule's execution, read back |
| `StoredRuleExecutions` | Every scheduled rule's execution, beside the state of the judging that produced them |
| `RuleExecution` | Everything one rule did to one bundle, and the unit the store commits |
| `MissingInput` | One declared attribute that was not captured, and how many objects it cost |
| `JudgementRunState` | What became of a judging run as a whole |
| `RuleExecutionOutcome` | What became of one rule within that run |
| `FindingsQuery` | What a findings grid asks for: which findings, and where to carry on from |
| `FindingsPage` | One page of findings, and whether there is another |
| `FindingsPageMark` | Where a page of findings ended, so the next can start after it |
| `FindingsFilterValues` | What a findings grid's filters may offer, taken from the findings that exist |
| `ControlCapability` | The supported bounded control capabilities, not the complete stage-6 catalogue |
| `ControlEdge` | A stored capability attributed to its named trustee, with evidence and independent expectedness |
| `ControlEdgeClass` | Semantic categories, never severity or an ordered risk score |
| `ControlEdgePage` | A bounded page with generation, coverage and counts, including hidden expected edges |
| `ControlEvaluationState` | Whether a capability is established, not established or unknown |
| `ControlExpectedness` | Whether control is expected, unexpected or not yet classified |
| `ControlExpectednessReason` | The stored reason for that separate classification |
| `ControlObjectEvaluation` | Per-object coverage, retained even when no edge can be identified |
| `ControlPrecondition` | A named condition with its own evaluation and evidence source |
| `ControlUncertainty` | Explicit unresolved inputs that limit a capability claim |

<!-- TYPES:END -->

---

## A bundle gains two files, and loses none

A captured bundle holds `evidence.db` and its seal. A judged one also holds `judgement.db` and
`judgement.db.seal`. Nothing opens the evidence for writing at any point, which is what lets the
same bundle be judged repeatedly while still proving what the directory said once.

`BundleLayout` owns all five names, as it owns every other name in a bundle, so no caller composes
one by concatenation.

**The store is disposable and that is a feature.** If an index is wrong, or a rule is improved,
the file is deleted and the bundle judged again. Nothing is lost, because the evidence was never
part of it.

---

## `judgement.db.partial`, then a rename

Judging writes to `judgement.db.partial`. The seal is written and the file renamed only once every
scheduled rule has finished. A reader asks for `judgement.db` and nothing else.

So a judging killed halfway leaves no file by the name a reader wants. This matters more here than
it does for capture: a half-judged bundle presenting the findings it managed to write looks exactly
like a forest with fewer problems than it has.

---

## The store names the capture it judged

`judgement.evidence_seal` holds the SHA-256 the evidence seal carries, and a reader refuses a store
whose value does not match the bundle it was opened beside.

This exists because the store is an ordinary file that can be copied. Two captures of one forest a
week apart produce directories with identical names holding mostly the same objects, so a judgement
moved into the wrong bundle would resolve nearly all of its findings and be wrong about every one of
them. The evidence seal is a permanent fingerprint of exactly one capture — taken once at the end of
capture and never reissued — which makes it the one value that can settle the question.

Copying a store between bundles is possible and unsupported. The check is what makes the attempt
fail loudly rather than silently.

---

## What ran is recorded, not inferred

`rule_execution` carries one row per scheduled rule, whatever became of it.

**This is what makes an empty `finding` table readable.** No findings and no execution rows means
nobody judged this bundle. No findings beside execution rows means every rule ran and nothing
matched. A screen with only the findings to go on would print both as a clean forest.

A rule that was scheduled and never executed gets a row too, with `RuleExecutionOutcome.DidNotRun`,
because an absent row cannot tell *never scheduled* from *scheduled and skipped*.

`objects_judged`, `objects_not_applicable` and `objects_not_judged` are three different answers and
none is derived from the others.

**Not applicable is not a gap.** A rule declares the classes it is about, and an organisational unit
offered to a delegation rule is not an object the rule failed to read — it has no
`userAccountControl` because it is not an account. Judged against a real forest on 2026-08-26 the
delegation rules called 6,279 of 8,361 objects unreadable on exactly that account, three in four,
which would have reported every judging as degraded for ever and taught an operator to ignore the
one signal that says the findings are incomplete.

**`objects_not_judged` is the real gap**: an object the rule *is* about, missing something the rule
declared it reads. That still degrades the run, and still should.

`rule_execution_missing_input` says which declared attributes were absent and on how many objects.
That turns *SEC-010 could not judge 4,000 objects* into *`primaryGroupID` was not captured*, which
is the difference between a mystery and an instruction.

---

## Two state machines, because a run and a rule fail differently

<!-- STATES:BEGIN -->

| `JudgementRunState` | What it means |
|---|---|
| `Running` | One or more scheduled rules has no terminal execution record, which includes the process being killed mid-run |
| `Completed` | Every scheduled rule reached a terminal, non-degraded result |
| `CompletedDegraded` | Every scheduled rule reached a terminal result, but one or more was indeterminate, errored or did not run |
| `Failed` | The coordinator itself failed — scheduling, sealing or recording the result |

| `RuleExecutionOutcome` | What it means |
|---|---|
| `Succeeded` | The rule ran and reached a verdict on every object it was offered |
| `Indeterminate` | The rule ran and could not reach a verdict on one or more objects, because a declared input was not captured |
| `Error` | The rule threw. Other rules continue; this one has no verdict |
| `DidNotRun` | The rule was scheduled and never executed |

<!-- STATES:END -->

`Failed` and an interrupted `Running` are not the same thing. One is a defect in this product; the
other is a claim about a customer's directory, and a store that could not tell them apart would
present a coordinator that never started as a judging that found nothing.

`CompletedDegraded` is not a lesser kind of success. A judging where a rule could not read its
declared inputs has not established that the forest is clean of what that rule looks for.

---

## Writing is atomic per rule, not per run

Each rule's findings commit in one transaction together with its own execution record.

The two alternatives both lose something. One transaction for the whole run throws away every
completed rule when the last one fails. No transaction boundary at all leaves findings written with
nothing saying which rule produced them. Committing per rule means a killed process loses only the
rule that was running, and no finding can exist without the record of what produced it.

---

## Derived evidence is bound to its generation

`judgement.derivation_generation_id` identifies the derivation used by a judging that requires one.
Schema 14 also persists SEC-021's grouped membership evidence and completeness using the same
`MembershipRouteStorage` encoding as Derivation. The finding carries its protection catalogue version
and any direct catalogue basis. Opening or paging it therefore does not reconstruct routes from a
newer derivation or silently lose longer alternatives.

An incomplete verdict may retain established findings beside its unresolved inputs. A rule that
throws still loses its entire output. This distinction was exercised end to end with a known
protected account and an unresolved membership elsewhere in the captured graph.

### Initial control-edge product — schema 15

**Historical baseline; the current product is schema 16, described below.**

`JudgingRun` now calls `ControlEdgeDeriver` for each streamed object and persists its result through
`JudgementWriter`. `ControlEdgeStorage` records product completion, per-object descriptor coverage,
edges, supporting ACEs and preconditions. Membership evidence is stored with each edge rather than
reconstructed from a later derivation.

The supported primitives are `CanWriteDacl` and `CanSetOwner`. The supporting
`CanBecomeOwnerAndRewriteDacl` compound remains `Unknown`, research-blocked and uncounted; a proved
owner-setting right does not prove a takeover. Expectedness and capability evaluation are separate.
`JudgementReader.ReadControlEdges` supplies object-first and named-holder-first pages from the same
stored product. The object screen defaults to hiding expected edges, states their count, shows
coverage and evidence, and refuses to mix generations while paging.

This was a started slice, not completed stage 6. Ownership-derived control, membership changes,
credentials, replication, full-control aggregation and effective member expansion are not derived.
Reachability remains unbuilt. The end-to-end witness is
`JudgingEndToEndTests.SealedDescriptorProducesStoredControlEdgesThroughTheRealCoordinator`;
automated tests do not discharge the stage's claim-specific laboratory gates or P-145.

### Bounded group-membership control — schema 16

**Implemented, not laboratory-accepted.** `ControlEdgeDeriver` now asks two separate questions
on captured group objects. Neither category nor target class says that the group is privileged.
Known non-group objects are excluded; a missing target class is an explicit coverage gap.

| Capability | What is established from permissions | What is not claimed |
|---|---|---|
| `CanModifyGroupMembership` | WRITE_PROPERTY (`0x20`) reaches `member`, without the own-account restriction | That every proposed membership value would pass AD's group-scope, value or other directory constraints; that the group is Tier 0 |
| `CanAddSelfToGroup` | A separate Self-Membership validated-write (`0x08`) candidate, with `HoldsSelfMembershipValidatedWrite` recording the permission answer | That a concrete requester can perform the operation. `AddedMemberSid == RequesterSid` stays `Unknown`; only the caller's own account may be added or removed |

**Why even a directly named self-membership candidate stays unknown in this bounded slice:**
the analysis does not identify and evaluate a concrete acting requester. A named trustee, including
a group or a broad identity, is not itself proof of that requester. The stored permission answer
can be established while the constrained operation stays unknown. This is an implementation limit,
not a new AD rule or acceptance of the stage-6 proposal's direct-requester claims. Group-held
self-membership expansion remains gated under `0110`; no member capabilities are generated.
An unknown self-membership candidate does not weaken an independent general membership write.

**The external anchor is Microsoft's distinction, not agreement between tests and code.**
[Control Access Rights](https://learn.microsoft.com/windows/win32/ad/control-access-rights)
defines WRITE_PROPERTY as 32 and validated SELF as 8, and explicitly limits Self-Membership to
the caller's account. [Self-Membership](https://learn.microsoft.com/windows/win32/adschema/r-self-membership)
gives its GUID and group target. The existing Microsoft-anchored `SchemaGuidCatalog` supplies
GUIDs rather than duplicating literals. `member` and Self-Membership share a GUID but not a right.

**Attribute and property-set entries are evaluated together, in stored order.** A temporary
projection selects only the entries reaching the one membership operation, then calls the existing
`EffectiveAccessCalculator`. Evaluating property sets separately and unioning answers would let a
property-set allow escape an attribute deny. A property set reaches `member` only when the captured
catalogue says it contains that attribute; no shipped membership list is assumed. Unknown property
scope, incomplete descriptors, unsupported/callback ACEs and relevant cross-trustee denies retain
unknown candidates. Inherit-only entries grant nothing on this object. NULL, empty and unread
descriptors remain distinct. Generic rights arrive mapped through the existing parser/normalizer.

**Stored evidence is not the projection.** Original ACE ordinals, trustees (including an original
SELF placeholder), masks, GUID flags, inheritance and callback bytes are retained, together with
the captured property-set explanation, requester constraint, descriptor outcome, generation and
existing membership routes. Both capabilities use `MembershipEscalation` under `0110`. Expectedness
still uses catalogue 2 and accepted authority scopes, including the P-150 correction; ownership
acceptance, protection and target privilege are not substitutes. The two existing views read these
same stored rows and expose the distinct wording, uncertainty and constraints.

**Counting is still named-holder counting, not member counting.** Each capability candidate is
counted once per target and scoped trustee; unknown candidates are included, explicitly labeled,
and keep object coverage incomplete. Expectedness counts are not counts of established operations.
The owner-to-DACL compound remains unknown and uncounted. Effective member expansion, ownership-
derived control, credential and replication capabilities, full-control aggregation and reachability
remain outside this work.

**Schema 16 and control engine 2 are semantic changes, not evidence or table-layout changes.**
Schema-15 judgements are refused and must be re-judged; an engine-1 product cannot claim membership
coverage. The schema-15 independent layout checkpoint remains untouched, and schema 16 explicitly
shares that layout. Semantic tests therefore accompany the layout check. No re-capture or
re-derivation is required. Principal catalogue version remains 2.

**Automated witnesses:** `GroupMembershipControlTests`,
`ControlEdgeStorageTests.MembershipKindsConstraintsAndOriginalAcesSurviveBothQueries`,
`JudgingEndToEndTests.SealedGroupDescriptorProducesSeparateMembershipCapabilities` and
`ControlEdgePresentationTests.BothViewsKeepGeneralAndSelfMembershipSeparateAndShowTheirLimits`.
The coordinator tests use newly created isolated synthetic bundles, including generic-write and
generic-all descriptors. The initial targeted run passed all 64 tests across membership analysis,
storage, layout, coordinator and presentation. The final full run passed **3,390 tests**, with none
failed or skipped, compared with the checkpoint's 3,356. The solution build succeeded.

**Observed negative control:** temporarily replacing the self-membership mask `0x08` with `0x20`
made both `SameGuidDoesNotMergeDifferentRights` cases fail. The WRITE_PROPERTY case reported
`Assert.Single` with two rows; the SELF case reported an empty collection. Neither case passed.
The correct mask was restored before the green full run. Existing layout mutation tests still
reject added columns and missing indexes; the old-schema tests refuse both 14 and 15, and the
engine-version negative control refuses engine 1 under the new scope.

**Validation findings, closed:** the older whole-object test fixture omitted its target class;
making its intended OU class explicit preserved its original assertions while the missing-class
test still proves the unknown boundary (test-fixture severity: low). The new engine-refusal fixture
initially opened a legacy filename instead of the generation product; it now mutates only its own
synthetic partial store before publication (test-fixture severity: low). Final review also corrected
SYSTEM self-membership expectedness to `UnknownCapabilityScope`, rather than claiming an incomplete
descriptor when the unresolved input is the requester operation (presentation severity: medium).
`SystemRequesterUncertaintyIsNotMislabelledAsAnUnreadDescriptor` guards that distinction.
`DuplicateGrantsDoNotMultiplyTheNamedHolderOrInvokeMemberExpansion` verifies the bounded count and
fails if the analysis calls member expansion.

**The implementation test run above did not claim a laboratory measurement.** The separate
schema-16 offline comparison below now records one, without discharging live requester gates.
The schema-15 corrected baseline remains 65,084
counted primitives: 53,265 expected, 11,805 unexpected and 14 of unknown expectedness. It does not
include these new membership candidates. No sealed laboratory evidence or `next/artifacts/` was
modified or reused for writes. P-145 and the remaining stage-6 laboratory gates remain open;
completed permission/Tier 0 session briefs are historical and the stage-6 specification remains
a proposal except where accepted decisions govern it.

### Isolated live Self-Membership measurement — 2026-09-06

**AD behavior measured; requester analysis and member expansion still unimplemented.**
`next/tools/Test-LabSelfMembership.ps1` created fresh non-privileged objects under
`OU=SecureAD-SelfMembership-saSM6d575afc,DC=ba,DC=ad,DC=lab` on `BADC.ba.ad.lab`.
The two target groups have protected DACLs: Domain Admins and SYSTEM retain administrative access,
Authenticated Users has read access, and the test trustee has only object-specific SELF (`0x08`)
for the Self-Membership GUID. There is no general membership-write grant for either test trustee.
The direct trustee is one temporary user; the other trustee is a temporary global security group
containing a different temporary user. Neither target nor grant-holding group is privileged.

Each measured modify used a fresh, explicitly authenticated LDAP connection with signing and
sealing as the temporary caller, not the administrator. Binding errors cannot count as refused
modifies. Membership was read before and after each request; deletion tests started with the
member present. Administrator setup also demonstrated that the other account was a legal member
value. Twelve assertions passed:

| Grant | Caller adds/removes itself | Caller adds/removes another account |
|---|---|---|
| Direct Self-Membership | Both succeeded, LDAP 0; membership changed exactly as requested | Both refused, LDAP 50; membership unchanged |
| Self-Membership through one global security group | Both succeeded, LDAP 0; membership changed exactly as requested | Both refused, LDAP 50; membership unchanged |
| No-grant control, tested with both callers | All four operations refused, LDAP 50; membership unchanged | Not measured on this control |

**Fresh evidence and readback.** The CLI captured all three domains into
`ad.lab-20260906-053214`, containing 8,407 objects, including the eight objects in the successful
test OU and sixteen retained objects from incomplete setup attempts. Evidence SHA-256:
`137FF0CE603D5CC6463C76D1FA0432245A57C2FC1FF48481BDDDA9C6A8B8DA41`.
Derivation generation: `9059ced8-4300-431f-a5ce-e959d3e4d15a`; judgement generation:
`b3ba397d-3a48-43dc-bec5-2b48302be4dc`. Judging remains `CompletedDegraded`: 27 findings,
with SEC-031 and SEC-032 each indeterminate on four objects. This is not a complete all-rule pass.

The read-only comparison under `next/artifacts/self-membership-live-20260906-0527/` verifies
the successful run's object GUIDs, disabled users, grant-group membership and two exact SELF-only
grants. Raw captured ACE ordinals, trustees, masks and GUIDs match their stored supporting entries.
The live recorder uses `ActiveDirectorySecurity`, which normalizes entry order; the same
representation of captured bytes matches that live DACL. Raw ordering is checked separately with
`RawSecurityDescriptor`, not silently compared with the normalized display.

Both named holders have exactly one membership candidate on their respective targets:
`CanAddSelfToGroup`, permission precondition `Established`, operation `Unknown`, and
`AddedMemberSid == RequesterSid: Unknown`. Neither has general membership control. Both actual
object-first and holder-first reader/presentation paths return identical evidence and retain the
own-account/requester limitation. The grant group's member has no expanded edge, and the view
states that it is not a member expansion. No-grant candidates are absent. Altered-mask and
missing-representative negative controls were detected. **These are programmatic checks of the
real presentation classes, not a visual GUI inspection.**

**Retention and cleanup.** The owner chose to retain the objects. All nine temporary users across
the three attempts were disabled; passwords were never persisted. Each attempt has its own
`live-results.json` manifest, with GUIDs and directory names:

| Artifact subfolder | Retained OU under `DC=ba,DC=ad,DC=lab` | Outcome |
|---|---|---|
| `live` | `SecureAD-SelfMembership-saSMf2f33e85` | Incomplete: ADSI property adapter intercepted `Options`; corrected with `psbase` before retry |
| `live-retry` | `SecureAD-SelfMembership-saSM2f44e696` | Incomplete: built-in `measure` alias intercepted the helper; renamed before retry |
| `live-final` | `SecureAD-SelfMembership-saSM6d575afc` | All twelve live assertions passed |

Each OU contains users named with its `saSM` tag and suffixes `-D`, `-G`, `-O`, plus groups with
suffixes `-DirectTarget`, `-GroupTarget`, `-GrantHolders`, `-NoGrant`. The two setup findings are
closed harness defects, not failed authorization measurements. Their artifacts remain separate.
To preview cleanup, run `next/tools/Remove-LabSelfMembership.ps1` with `-ManifestPath` pointing to
one attempt's manifest and `-WhatIf`. Omit `-WhatIf` only when ready to confirm deletion. The
helper verifies GUIDs, names, ownership markers and the entire OU inventory, refuses extra objects,
and never recursively deletes or removes evidence files. Cleanup was not executed.

**Final verification:** solution build succeeded; all 3,390 tests passed, with none failed or
skipped. Nineteen script checks passed, including cleanup previews for all three OUs and refusals
for wrong scope, an unrecorded child, duplicate identity and reuse of an existing result directory.
All 238 pre-existing artifact file fingerprints were unchanged (transient SQLite WAL/SHM files
excluded); the fresh Evidence hash also remained unchanged. Read-only inventory confirmed all
24 retained objects and all nine users disabled. `validation.json` beside the inspection records
the checks; no credentials are included.

This measurement supports the own-account-only AD behavior in these two isolated grant shapes.
It does not implement concrete requester evaluation, accept arbitrary nested/token scenarios,
classify any target as Tier 0, or close P-145 and the remaining stage-6 acceptance gates.

### Captured-lab validation of the initial slice — 2026-09-06

**The catalogue-1 baseline, not stage-6 acceptance.** A fresh evidence-only copy of
`ad.lab-20260905-212426` was derived and judged before the P-150 correction below. This is the newer capture
used by the interrupted session, not the older `03:54` capture named in its brief. All three domains
and 8,383 captured objects were represented. The source, preserved previous copy and new copy retain
Evidence SHA-256 `2DEF9F8AD4DE01877970B7F97F845716C1FFC1B093B01F388004610526E76BE4`.
No directory connection or modification was made.

| Initial-slice measurement | Result |
|---|---:|
| Counted WRITE_DAC primitives | 32,544 |
| Counted WRITE_OWNER primitives | 32,540 |
| Expected primitives | 43,447 |
| Unexpected primitives | 11,805 |
| Expectedness unknown | 9,832 |
| Supporting owner-to-DACL compounds, unknown and uncounted | 32,540 |
| Objects with unanswered supported primitives | 0 |

All 65,084 primitives have evaluation `Established`. **That is separate from whether a right is
expected**, and neither this table nor zero unanswered supported primitives means all stage-6
capabilities were evaluated. Judging produced 27 findings; SEC-031 and SEC-032 each retained their
four unresolved objects, so the overall run remains `CompletedDegraded`.

**The byte-level check did not call SecureAD's parser or access evaluator.** The .NET
`RawSecurityDescriptor` reader parsed the 390 distinct captured descriptors. Its entry ordinals,
types, SIDs, masks, GUID presence, inheritance flags and opaque data matched the 1,547 distinct
supporting signatures representing all 433,561 stored control-ACE records. Generic mapping and
inherit-only interpretation follow [MS-ADTS 6.1.3](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/081c41f0-4c8d-4ab0-971d-77ec2504375a).
Every counted primitive had an applicable raw allow, and independently enumerating uncomplicated
direct grants found the same 65,084 identities with none omitted. Altering a compared ACE and
removing an edge in memory each made the corresponding check detect the mismatch. These checks
establish provenance and direct-grant coverage, not token-wide effective access.

The previous and fresh generations have identical edge answers and object coverage after excluding
generation identifiers. The planted `SecureADTakeoverOuter` group retains two unexpected primitives
on `OU=SecureADTakeoverTarget,OU=BA Lab,DC=ba,DC=ad,DC=lab` and one unknown, uncounted compound.
Object-first and holder-first reader calls return the same edge identities. The target has 15 stored
rows, seven default-visible rows and six hidden expected primitives; supporting rows are not added
to those primitive counts. An absent target is not presented as a complete empty result.

**The baseline exposed P-150, since corrected below.** All 9,818 `UnknownAuthorityScope`
primitives belong to `BUILTIN\Administrators`: 460 scoped to `ad.lab`, 8,834 to `ba.ad.lab` and 524
to `ph.ad.lab`. The three scoped group objects are captured. `ObjectPermissions` deliberately gives
well-known SID labels no domain; the original `ControlEdgeDeriver` recorded a scoped holder but passed the
unscoped label's domain into its direct expectedness check. Decision `0099` accepts Administrators
within its own domain. The missing scope handoff was the defect, not the accepted catalogue.
Do not resolve a shared BUILTIN SID
by taking the first matching directory row, or remove the uncertainty required for non-domain
resource contexts under P-90.

**Unexpected volume has two large concentrations.** Account Operators contributes 8,426 primitives
(4,260 on groups, 4,120 on users, 24 on foreign security principals, 16 on computers and six on group
managed service accounts). Forest-root Domain Admins contributes 3,210 outside its accepted authority
scope. A large count does not by itself justify widening the catalogue. SYSTEM contributes 16,732
expected primitives; ADDC, BADC and PHDC each contribute six unexpected primitives. Server Operators,
Print Operators, Backup Operators and Replicator have no named-trustee primitives in this slice;
that is not a claim that they have no other capabilities. Enterprise Domain Controllers accounts for
the remaining 14 unknown expectedness answers, with `UnknownCapabilityScope`.

Artifacts, including the two executable checks, raw diagnostic outputs and binary fingerprints,
remain under `next/artifacts/stage6-control-recovery-validation/`. Judgement generation:
`4cfa848c-83c2-42b5-8eb9-c65014d07c72`; derivation generation:
`709c602a-19ad-428d-91bd-5d10efb507a6`. **P-145 remains open:** the remaining capabilities,
member expansion, Tier 0-target analysis and the claim-specific live laboratory gates are not
discharged by this offline check. No application behavior or policy was changed in the baseline pass.

### P-150 corrected — catalogue 2, 2026-09-06

`ControlEdgeDeriver.Expected` now obtains direct BUILTIN domain authority from the target's domain
only when the target is in that domain naming context and its captured domain root supplies a SID.
The well-known label remains domainless. Configuration, schema, application-partition and missing-
scope cases remain unknown; a membership route retains its root's own recorded scope. No first-match
SID lookup or new expected principal was introduced.

`PrincipalClassificationRegistry.Version` is now 2. The storage layout remains judgement schema 15:
new edges carry the changed semantic version, and old generations are read as recorded, not relabeled.
**Re-judge existing evidence to obtain the correction; re-capture and re-derivation are not required.**

The regression uses a real two-domain bundle containing both Administrators groups and real
descriptors, in both capture orders. It verifies that the reader's label is still domainless,
object-first and holder-first identities agree, scopes stay separate, expected primitives are hidden
with their count stated, and the supporting ownership compound remains unknown and uncounted.
Both cases failed before the fix with *expected 2 expected primitives, actual 0*. Two direct-scope
positive cases also failed; the negative scope and cross-domain membership-root cases passed.
After correction and versioning, all 60 targeted tests passed.

A separate copy of the same evidence and sealed derivation was judged into generation
`a0eef917-5c1b-493b-98bf-8b21bbcf63b4`. The preserved baseline was not overwritten.

| Counted primitive classification | Catalogue 1 | Catalogue 2 |
|---|---:|---:|
| Expected | 43,447 | 53,265 |
| Unexpected | 11,805 | 11,805 |
| Unknown | 9,832 | 14 |

Exactly 9,818 counted primitives changed from `UnknownAuthorityScope` to
`ExpectedSameDomainControlPlane`, all scoped BUILTIN Administrators. Another 4,909 supporting
compounds changed only their expectedness: their capability evaluation remains unknown and they are
still uncounted. Each domain already had two expected Administrators primitives; the corrected
holder totals are therefore 462 in `ad.lab`, 8,836 in `ba.ad.lab`, and 526 in `ph.ad.lab`, not merely
the reclassification deltas. The remaining 14 unknown answers still have `UnknownCapabilityScope`
for Enterprise Domain Controllers.

The executable comparison in `next/artifacts/stage6-p150-scope-correction/compare-p150.ps1` checks
both directions: all other stored edge fields (apart from the new generation and catalogue version),
8,383 object-coverage rows, 433,561 control ACEs, 97,620 preconditions, membership-route tables, 27
finding rows and all 17 rule-execution rows match the baseline. The evidence fingerprint is unchanged.
The real reader shows eight hidden expected primitives and four visible rows on the planted target;
the two unexpected takeover-group primitives remain visible. Opening the historical generation
still returns its version-1 answers. **P-150 is closed; P-145 and stage-6 acceptance remain open.**

### Schema-16 membership slice — offline lab comparison, 2026-09-06

**Checkpoint `491fbff`, not stage-6 acceptance.** The bounded membership slice was committed,
then the corrected schema-15 evidence and derivation were copied into a new, separate workspace
directory. The original `next/artifacts/` files were not used as writable working files. All twelve
files in the source bundle, including its existing SQLite sidecars, retain their original hashes;
all six database seals in the comparison baseline and final working copy verify.

The final judging used the baseline's exact evaluation time,
`2026-09-06T03:28:21.4277714+00:00`, so time-dependent rule inputs did not change. It completed in
108.95 seconds as generation `3fd5276e-66b3-4f1b-925f-0f3720672fff`, with judgement schema 16,
control engine 2 and principal catalogue 2. Derivation remains
`709c602a-19ad-428d-91bd-5d10efb507a6`; Evidence SHA-256 remains
`2DEF9F8AD4DE01877970B7F97F845716C1FFC1B093B01F388004610526E76BE4`.

**Existing answers did not change.** Comparing by target, scoped holder and capability, rather
than generation-local row numbers, found identical values for all 97,624 old edge rows, 433,561
supporting ACE rows, 97,620 preconditions and the existing membership-route evidence. The 8,383
descriptor-coverage records are unchanged apart from the explicitly broader completeness question
below. All 27 findings, their detail tables and all 17 rule-execution rows match. The judging outcome
remains `CompletedDegraded`. The 32,540 owner-to-DACL compounds remain unknown and uncounted.

| Counted slice | Expected | Unexpected | Expectedness unknown | Total | Capability evaluation |
|---|---:|---:|---:|---:|---|
| Existing WRITE_DAC/WRITE_OWNER | 53,265 | 11,805 | 14 | 65,084 | Established |
| General membership writes | 8,635 | 2,141 | 0 | 10,776 | Established |
| Own-account-only Self-Membership candidates | 6,457 | 2,141 | 2,163 | 10,761 | Unknown |
| All counted rows in these slices | 68,357 | 16,087 | 2,177 | 86,621 | Mixed; not a total of proven operations |

Both new capabilities occur across **2,163 captured groups**. Those groups now have incomplete
supported-capability coverage because their concrete self-membership requester operations are
unanswered, **not because descriptors were lost**. General membership-write answers remain
established independently. An expected self-membership candidate is still unknown as an operation;
the expectedness column does not establish the requester constraint.

**The unexpected membership volume is attributable, not unexplained.** Account Operators contributes
2,130 general writes and 2,130 self-membership candidates: 2,054 of each in `ba.ad.lab`, 40 in
`ph.ad.lab` and 36 in `ad.lab`. The principal named `ba.laps.new`
(`S-1-5-21-1834058357-2590327168-2246012571-1607`) contributes the other eleven of each, against
groups under `OU=Groups,OU=BA Lab`, including the LAPS-related groups. No wider authority was granted
to either holder by changing the catalogue. SYSTEM contributes 2,163 expected general writes and
2,163 self-membership candidates with unknown expectedness (`UnknownCapabilityScope`). The other
four excluded operator groups and the domain-controller computer accounts have no named-holder
membership candidates in this capture; that is not a claim about their other rights or expanded
membership. The renamed RID-500 account `jimmystrand` has fifteen additional general membership
writes, each supported by an object-specific READ_PROPERTY/WRITE_PROPERTY ACE on `member`, without
a corresponding Self-Membership candidate.

**Independent byte-level and coverage checks passed.** The .NET `RawSecurityDescriptor` reader,
not SecureAD's descriptor parser or effective-access calculator, verified 122 distinct ACE
signatures representing all 21,537 new stored membership ACE rows. Checks covered ordinal, type,
SID, mapped mask, GUID-presence flags, GUIDs, inheritance and opaque bytes. Independently enumerating
uncomplicated direct grants from the captured groups found the same 21,537 candidate identities,
with no omissions or additions, across all 2,163 groups. Changing a compared mask and omitting a
candidate in memory were both detected; the stable-store comparison also detected omitted old
edges and altered old ACE masks through read-only query mutations. No evidence file was mutated.

**Both reader directions agree.** Twenty-five representative rows cover every observed scoped
holder/capability combination. Object-first and named-holder-first calls returned identical full
edge evidence and generation identities. Toggling the object filter retained its expected count;
expected rows were hidden by default without changing their stored classifications. These are real reader checks, not a claim
that a person manually exercised the graphical interface.

**What this capture cannot validate:** all self-membership candidates also have a general-write
candidate for the same target and holder. There are **zero self-membership-only cases**, no relevant
denies, callbacks or inherit-only grants, and no property-set-based membership grants in this
measurement. The fifteen scoped grants reach `member` directly. Automated tests cover the absent
scope/deny/callback cases; this captured-evidence pass does not replace controlled live tests of
own-account versus other-account modification, especially through a trustee group. It also does
not establish token-wide effective authorization, member expansion, full Tier 0-target review,
remediation or the acceptability of the default result volume. **P-145 and the claim-specific
laboratory gates remain open.**

Local artifacts are deliberately untracked under `next/lab-validation-membership-491fbff/`:
`run-judging.ps1`, `compare-membership.ps1`, `inspect-membership.ps1`, `verify-integrity.ps1`, their
logs, JSON reports, source/binary manifests, a preserved baseline and isolated working copies.
The first diagnostic generation `f16f74a8-ce95-4af3-b252-3abb842227ea` is retained separately but
excluded from the comparison: PowerShell's automatic JSON date conversion discarded fractional
seconds. The final harness preserves date strings and refuses a reference time that does not
round-trip exactly. A catalogue-namespace typo stopped an earlier harness attempt before judging;
a later file-count alarm was JSON-array handling, with all twelve original files independently
confirmed unchanged. These were corrected harness defects, not product or evidence changes.

---

## Opening checks three different ways of being wrong

`JudgementReader.Open` refuses before it returns anything:

| Check | What it establishes | Refused as |
|---|---|---|
| The judgement seal | These bytes are the bytes that were written | `JudgementSealAbsent`, `JudgementSealUnreadable`, `JudgementSealMismatch` |
| The schema version | This build understands these tables | `JudgementUnreadable` |
| The evidence fingerprint | This judgement is about *this* capture | `JudgementIsNotForThisEvidence` |

The third is the one no care by the writer can establish, because a store is an ordinary file that
can be moved. A bundle with no readable evidence seal is refused on the same footing as a mismatched
one: unverifiable is not the same as verified, and passing it would make the check optional in
exactly the case where the bundle is already odd.

`BundleSealing.VerifyJudgement` does the seal half, sharing one implementation with the evidence
seal so there is one set of four states rather than two copies of it. `BundleSealing.ReadSeal` is
how a judgement gets the fingerprint to record.

---

## Findings never leave the reader on their own

`Read` returns a `StoredJudgement` carrying the findings **and** the rules that ran. There is no way
to ask for one without the other.

That is a type-system decision rather than a documentation one. A caller holding a bare list of
findings can render an empty one as a clean forest without ever asking whether a rule ran, and no
amount of warning in a comment prevents it. `StoredJudgement.DidNotRun` and
`StoredJudgement.EveryRuleReachedEveryVerdict` are the two questions a screen has to answer before
it shows a count.

---

## One pass over the bundle, not one per rule

`JudgingRun.Judge` opens the sealed bundle, streams every object once, and offers each to every
scheduled rule while it is in hand. Judging forty rules costs the same read as judging one, so
adding a rule costs comparisons rather than another walk of the forest.

**How long judging takes is not known, and the numbers measured here do not answer it.** Streaming a
synthetic bundle on the development machine reached 43,409 objects a second on 2026-08-26, but that
is the read alone with no rule running; with the two delegation rules it fell to roughly 4,689. Both
figures come from invented objects carrying a handful of attributes, and the owner's judgement is
that a synthetic bundle is not complex enough to stand in for a forest. **The number that should be
trusted instead is the predecessor's: four to five hours over the owner's production forest.**
Judging is built for that duration rather than for the lab's 0.72 seconds.

**So a judging reports progress and can be stopped.** `Judge` takes an `IProgress<JudgingProgress>`
and a `CancellationToken`, both required rather than defaulted — gate 1 records that progress,
cancellation and the performance log all became quietly unused in the predecessor by being optional,
and a caller with no operator to tell says so by passing `JudgingRun.NobodyIsWatching`.

Progress counts objects rather than a percentage, because nothing counts a bundle before streaming
it and a percentage wrong by a little would stall at 99 in front of someone watching for hours. It
is reported every 1,000 objects, and the final report is unconditional so that a run ending between
two batches does not leave a total short of what was read.

**Cancelling costs the operator nothing but the time it ran.** The partial file is never renamed
over the finished one, so the earlier judgement survives — the same protection a crash gets, by the
same mechanism. A cancel that destroyed the previous answer would teach an operator never to press
it.

**A rule that throws loses only itself.** It is recorded as `Error`, offered no further objects, and
the rules beside it carry on. Its findings are discarded, because a rule that failed part way
through has no verdict and its partial output would read as a complete one.

**Nothing in the coordinator decides what a run means.** Each rule's outcome follows from what it
did, and the run's state follows from those outcomes inside the writer. A coordinator that could
name the state would be able to call a judging complete while a rule had read nothing.

---

## Findings are read a page at a time

A grid cannot hold a forest, so `JudgementReader.ReadPage` hands back one page and where to carry on
from. The approach is the predecessor's, read on 2026-08-26 and taken because it is better than the
obvious alternative.

**A page starts where the last one ended, not at a row number.** `LIMIT` with an `OFFSET` makes the
database walk and discard every row before the page, so the hundredth page costs a hundred pages of
work. `FindingsPageMark` carries the sort values of the last row shown and the next page is the rows
after it, which costs one seek at any depth.

**The sort ends in the distinguished name, and that is load-bearing.** Findings sharing a severity
and a rule have no order between them otherwise, so a page boundary landing inside such a group
shows some of them twice and loses others — silently, and differently each run. A distinguished name
is unique within a forest, so no two findings can tie on all three.

**Ordered by rank rather than by the word.** The stored severity is the enum's name, so ordering on
it is alphabetical — Critical, High, Low, Medium — which puts Low above Medium on a security screen
and looks entirely normal.

**One row more than the page is fetched and not returned.** Its existence is how a page knows another
follows, without a second query counting rows nobody asked to see. There is deliberately no total:
*page 3 of 400* costs the 400 on every page.

**A judging where no rule ran is refused rather than paged as empty.** `Read` hands findings out
beside the rules that ran because an empty list means nothing on its own; a page cannot carry every
rule execution, so it refuses instead, and `FindingsPage.DidNotRun` keeps the distinction reachable
for a screen holding a page.

**Wildcards in a container's own name are escaped before they reach the query.** `%` and `_` are
legal in a distinguished name and mean something to a `LIKE`, so selecting `OU=Test_1` would
otherwise quietly also show findings from `OU=Test01`.

---

## What a filter may offer comes from the findings that exist

`ReadFilterValues` hands back the severities and rules some finding actually has, and a screen
builds its filter lists from those rather than from the enum.

**A filter that cannot be set to nothing.** A list written into a screen offers Critical whether or
not anything is critical, and an operator who picks it and gets an empty grid has learned only to
distrust the control. Taking the values from the data means every choice narrows to something.

**Severities come back worst first, by rank.** The same alphabetical trap as the grid: ordering on
the stored word puts Low above Medium, which on a filter list reads as a mistake rather than as a
sort.

**Empty lists carry the count of rules that ran.** Two unlike things wear the same empty list — a
judged bundle whose rules found nothing, and a bundle nobody judged — so `FindingsFilterValues`
carries `RulesRan` and `DidNotRun` tells them apart rather than leaving a screen to guess.

**Filtering is a question, not a position.** The values narrow what `ReadPage` is asked for, and
because the resulting list is a different list, a `FindingsPageMark` taken from the old one does not
carry over: it points at rows the new list may not contain.

---

## What every rule did is readable without the findings

`ReadRuleExecutions` hands back one `StoredRuleExecution` per scheduled rule and no findings at all.
It is the other half of the question `ReadPage` answers: a page of findings says what was wrong, and
this says what was checked — including the rules that checked and found nothing, which no list of
findings can contain.

**The count of findings comes from a grouped query, not from the rows.** `SELECT rule_id, COUNT(*)
FROM finding GROUP BY rule_id` is one small read; carrying the findings themselves to count them
would make a screen of eleven rules pay for every finding in the forest.

**`FindingsProduced` sits beside the outcome rather than being inferred from an empty grid.** A rule
recorded as `Succeeded` with zero findings judged everything it was about and established something.
One recorded as `Indeterminate` established nothing about the objects it could not reach. Both write
zero findings, and only the pair of values keeps them apart.

**The list comes back vouched, not bare.** `StoredRuleExecutions` carries the run's state and
`DidNotRun`, because an empty list of executions means either a bundle nobody judged or a judging
that stopped before it recorded anything. Until this read existed the executions were reachable only
through `StoredJudgement`, which says the same thing; handing them back on their own would have taken
that statement away from the one caller whose whole subject is what was and was not checked. Gate 4
caught the omission.

---

## What is built

The schema, the two state machines, the writer, the reader and the `JudgingRun` coordinator are built.
Judging runs the scheduled rules over sealed evidence and also writes the bounded control-edge
products described above. These slices are not completion of stage 6 or its acceptance gates.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| be certain a judging still in progress cannot be opened | `JudgementWritingTests.AJudgementInProgressHasNoNameAReaderAsksFor` |  |
| have a finished judgement named and sealed | `JudgementWritingTests.CompletingNamesTheStoreAndSealsIt` | 2026-08-26 |
| keep the previous answer when a re-judging dies part way | `JudgementWritingTests.AJudgingThatDidNotFinishLeavesTheEarlierOneIntact` |  |
| be certain a judging whose coordinator failed offers nothing to read | `JudgementWritingTests.AnAbandonedJudgingIsNotGivenAReadableName` |  |
| tell a judging where every rule reached a verdict from one where a rule did not | `JudgementWritingTests.EveryRuleReachingEveryVerdictIsCompleted` |  |
| be certain one unreadable input degrades the whole judging | `JudgementWritingTests.OneRuleThatCouldNotReadItsInputsDegradesTheJudging` |  |
| keep the rules around one that threw | `JudgementWritingTests.ARuleThatThrewDoesNotCostTheRulesAroundIt` |  |
| see which capture a judgement was made against | `JudgementWritingTests.TheStoreRecordsTheEvidenceItJudged` |  |
| be certain a rule cannot claim every verdict and also have missed objects | `JudgementWritingTests.ARuleThatReachedEveryVerdictCannotAlsoHaveMissedObjects` |  |
| be certain an unreached verdict says what was missing | `JudgementWritingTests.ARuleThatCouldNotReachAVerdictMustSayWhatWasMissing` |  |
| see what was missing named rather than counted | `JudgementWritingTests.WhatWasMissingIsRecordedByName` |  |
| be certain a finding is not filed under a rule that did not make it | `JudgementWritingTests.AFindingCannotBeFiledUnderAnotherRule` |  |
| be certain a rule that threw does not leave half a verdict behind | `JudgementWritingTests.ARuleThatThrewCannotAlsoCarryFindings` |  |
| be certain one rule is recorded once | `JudgementWritingTests.OneRuleCannotBeRecordedTwice` |  |
| be certain nothing is added to a sealed judgement | `JudgementWritingTests.NothingCanBeAddedAfterTheJudgementIsSealed` |  |
| tell a rule that was skipped from one that was never scheduled | `JudgementWritingTests.ARuleThatDidNotRunIsStillRecorded` |  |
| have a finding survive into a sealed judgement and come back out | `JudgementReadingTests.AFindingComesBackFromASealedJudgement` |  |
| see the evidence a finding rests on come back with it | `JudgementReadingTests.TheEvidenceAFindingRestsOnComesBackWithIt` |  |
| be certain the domain-controller signals are rebuilt rather than trusted | `JudgementReadingTests.TheDomainControllerSignalsAreRebuiltFromWhatWasStored` |  |
| see which version of a rule produced a finding | `JudgementReadingTests.AFindingCarriesTheVersionOfTheRuleThatMadeIt` |  |
| tell a bundle nobody judged from one where every rule ran and nothing matched | `JudgementReadingTests.ABundleNoRuleWasRunOverSaysSoRatherThanLookingClean` |  |
| be certain that distinction is not made by a reader that says it of everything | `JudgementReadingTests.ABundleWhereRulesRanAndNothingMatchedIsNotTheSameThing` |  |
| see what a rule could not read, by name | `JudgementReadingTests.WhatARuleCouldNotReadComesBackNamed` |  |
| see which capture a judgement was made against | `JudgementReadingTests.TheJudgementNamesTheCaptureItWasMadeAgainst` |  |
| be certain a judgement from another capture is refused rather than believed | `JudgementReadingTests.AJudgementMadeAgainstAnotherCaptureIsRefused` |  |
| be certain a judgement that cannot be checked is refused too | `JudgementReadingTests.AJudgementWithNoEvidenceSealToCheckAgainstIsRefused` |  |
| be certain a judging that never finished cannot be opened | `JudgementReadingTests.AJudgingThatNeverFinishedCannotBeOpened` |  |
| be certain a judgement edited after sealing is refused | `JudgementReadingTests.AJudgementThatWasEditedAfterSealingIsRefused` |  |
| be certain the same finding from two judgings keeps one identity | `JudgementIdentityTests.TheSameFindingFromTwoRunsKeepsOneIdentity` |  |
| keep a finding attached to an object that was renamed and moved | `JudgementIdentityTests.AnObjectThatWasRenamedAndMovedIsStillTheSameFinding` |  |
| be certain tightening a rule does not orphan the findings made under it | `JudgementIdentityTests.TighteningARuleDoesNotChangeTheIdentityOfItsFindings` |  |
| see two rules about one object as two findings | `JudgementIdentityTests.TwoRulesAboutOneObjectAreTwoFindings` |  |
| see one rule against two objects as two findings | `JudgementIdentityTests.OneRuleAgainstTwoObjectsIsTwoFindings` |  |
| be certain one finding cannot be stored twice and shown twice | `JudgementIdentityTests.TheSameFindingCannotBeStoredTwiceInOneJudgement` |  |
| be certain evidence that may be missing confidential values does not come back complete | `JudgementIdentityTests.AFindingWhoseEvidenceMayBeIncompleteDoesNotComeBackComplete` |  |
| be certain that is not said of everything | `JudgementIdentityTests.AFindingWhoseEvidenceWasCompleteComesBackComplete` |  |
| be certain evidence with no table is refused rather than quietly dropped | `JudgementIdentityTests.AnEvidenceKindWithNoTableIsRefusedRatherThanDropped` |  |
| see an account trusted for delegation found in a sealed bundle | `JudgingEndToEndTests.AnAccountTrustedForDelegationIsFoundInASealedBundle` | 2026-08-26 |
| be certain a domain controller is not reported for a setting it requires | `JudgingEndToEndTests.ADomainControllerIsNotReported` | 2026-08-26 |
| be certain every scheduled rule is recorded whether it found anything or not | `JudgingEndToEndTests.EveryScheduledRuleIsRecordedWhetherItFoundAnythingOrNot` | 2026-08-26 |
| see which attribute was missing when a rule could not reach a verdict | `JudgingEndToEndTests.AnObjectMissingADeclaredInputDegradesTheJudgingAndNamesTheAttribute` |  |
| be certain a judgement is bound to the bundle it judged | `JudgingEndToEndTests.TheJudgementIsBoundToTheBundleItJudged` | 2026-08-26 |
| judge a bundle again without the earlier judgement being added to | `JudgingEndToEndTests.JudgingTwiceReplacesTheEarlierJudgement` |  |
| be certain an object a rule is not about does not make the judging look degraded | `JudgingEndToEndTests.AnObjectTheRuleIsNotAboutDoesNotDegradeTheJudging` | 2026-08-26 |
| be certain an account genuinely missing an input still degrades it | `JudgingEndToEndTests.AnAccountMissingADeclaredInputStillDegradesTheJudging` |  |
| see how far a judging has got | `JudgingEndToEndTests.AJudgingReportsHowFarItHasGot` |  |
| be certain the last count reported is everything that was read | `JudgingEndToEndTests.TheLastProgressReportedIsEverythingThatWasRead` |  |
| stop a judging that is running | `JudgingEndToEndTests.AJudgingStopsWhenItIsAskedTo` |  |
| keep the earlier judgement after cancelling a re-judging | `JudgingEndToEndTests.CancellingARejudgingLeavesTheEarlierJudgementIntact` |  |
| read one page of findings and be told there is more | `FindingsPagingTests.APageHoldsWhatItWasAskedForAndSaysThereIsMore` |  |
| be certain the last page says there is nothing after it | `FindingsPagingTests.TheLastPageSaysThereIsNothingAfterIt` |  |
| be certain a page that exactly empties the findings offers no empty page after it | `FindingsPagingTests.APageThatExactlyEmptiesTheFindingsHasNothingAfterIt` |  |
| be certain reading every page shows every finding exactly once | `FindingsPagingTests.ReadingEveryPageShowsEveryFindingExactlyOnce` |  |
| see the worst findings first | `FindingsPagingTests.TheWorstFindingsAreOnTheFirstPage` |  |
| narrow a grid to one severity | `FindingsPagingTests.AskingForOneSeverityReturnsOnlyThatSeverity` |  |
| narrow a grid to one rule | `FindingsPagingTests.AskingForOneRuleReturnsOnlyThatRulesFindings` |  |
| narrow a grid to one container | `FindingsPagingTests.AskingForOneContainerReturnsWhatIsBeneathIt` |  |
| be certain a container whose name holds a wildcard does not widen the grid | `FindingsPagingTests.AContainerHoldingAWildcardDoesNotWidenTheGrid` |  |
| be certain a bundle nobody judged is refused rather than shown as a clean grid | `FindingsPagingTests.AJudgingWhereNoRuleRanIsRefusedRatherThanPagedAsEmpty` |  |
| tell that apart from a judging that ran and matched nothing | `FindingsPagingTests.AJudgingThatMatchedNothingGivesAnEmptyPage` |  |
| be certain severity orders by seriousness rather than alphabetically | `JudgementReadingTests.SeverityIsStoredSoThatTheWorstSortsFirst` |  |
| offer a filter only the values some finding actually has | `FindingsPagingTests.TheFilterValuesAreOnlyWhatTheFindingsHave` |  |
| read a filter's severities worst first rather than alphabetically | `FindingsPagingTests.TheFilterSeveritiesComeBackWorstFirst` |  |
| be certain empty filters from a bundle nobody judged say so | `FindingsPagingTests.FilterValuesFromABundleNobodyJudgedSaySoRatherThanLookingEmpty` |  |
| tell that apart from a judging that ran and matched nothing | `FindingsPagingTests.FilterValuesFromAJudgingThatMatchedNothingSayTheRulesRan` |  |
| narrow the findings grid by severity or rule from the screen | `AssetsViewModelTests.ChoosingASeverityNarrowsWhatIsAskedFor`, `AssetsViewModelTests.ChoosingARuleNarrowsWhatIsAskedFor` |  |
| stop narrowing without asking for a rule called "Any" | `AssetsViewModelTests.ClearingTheFiltersStopsNarrowing` |  |
| be certain changing a filter does not open the grid part way down a list that no longer exists | `AssetsViewModelTests.ChangingAFilterStartsTheGridAgainAtItsFirstPage` |  |
| be certain an empty filtered grid does not claim the container is clean | `AssetsViewModelTests.AnEmptyFilteredGridDoesNotSayTheContainerIsClean` |  |

**Confirmed in lab** is the date the owner saw this working against a real forest.

**On 2026-08-26 a finding this product computed reached a screen for the first time.** The owner ran
an audit in the application, pressed *View results*, and read it. Everything above it — capture,
seal, stream, judge, store, page, show — ran in one gesture with nobody at a command line. The run
before that one crashed on a resource key that never existed, which is why
`ViewResourceGateTests` was written.

**Dates are not filled in from that run beyond what it actually exercised.** A run producing a
handful of findings does not confirm a second page, an empty page, or a wildcard in a container
name, and a date against those rows would say the owner had seen something he had not.

**2026-08-26 is the first lab confirmation this product has recorded.** A bundle captured from
`ph.ad.lab` — 8,361 objects — was judged in 0.72 seconds. Both rules reported `Succeeded`, judging
2,082 accounts and passing over 6,279 objects they are not about. One finding: an account planted
for the purpose, `CN=lab.unconstrained`.

**The domain-controller exclusion was confirmed separately, and the first draft of this paragraph
claimed it without grounds.** No controller appeared in the findings, and that had three
explanations — the exclusion worked, the controller does not carry `TRUSTED_FOR_DELEGATION`, or it
was never judged. An absence cannot choose between them, so `judge-bundle.ps1 -Explain` was built to
ask the bundle directly. Against `CN=PHDC,OU=Domain Controllers,DC=ph,DC=ad,DC=lab` it reported
`userAccountControl` 532480 — `SERVER_TRUST_ACCOUNT` and `TRUSTED_FOR_DELEGATION` together — all
three controller signals agreeing, and SEC-011 reaching a verdict of nothing to report. That is the
second explanation eliminated and the third with it: SEC-011 is the computer rule, PHDC is a
computer the rule is about, and the coordinator offers every object in the bundle to every
scheduled rule, so the object the rule judged here is the object it judged in the run. What stood
between a real controller and a finding was the exclusion, and nothing else.

**The same was then observed in every other domain.** The forest carries three controllers, one per
domain, and all three read alike: `CN=baDC,OU=Domain Controllers,DC=ba,DC=ad,DC=lab` and
`CN=adDC,OU=Domain Controllers,DC=ad,DC=lab` each gave `userAccountControl` 532480, all three
signals agreeing, SEC-011 judging them and reporting nothing. So the exclusion holds across a
naming-context boundary, and at the forest root as well as in a child domain — the two places the
organisational-unit signal reads a differently shaped distinguished name.

**A guess about that boundary was wrong and is recorded because it was wrong.** The expectation was
that a controller in another domain is where the three signals part company — the primary-group
check looks for RID 516 or 521, which is domain-relative, and the organisational-unit check reads a
distinguished name in a different partition. Neither faltered. `SignalsDisagree` therefore still has
no lab exercise, and now demonstrably cannot get one here: every controller this forest has been
asked about, and all three agree with themselves. The disagreement path remains proven by test
alone, and the reason it has not been seen is that a healthy forest does not appear to contain such
an object.

The other blank rows were not exercised: nothing threw, no rule was skipped, and no account was
missing a declared input, so the refusals and degraded paths remain proven by test alone.
