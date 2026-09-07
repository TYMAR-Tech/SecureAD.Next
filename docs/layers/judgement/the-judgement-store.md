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
| `SelfMembershipRequest` | One explicit user, target group and add/remove own-account question |
| `SelfMembershipBudget` | Deterministic limits for a bounded requester batch |
| `SelfMembershipAssessment` | Stored authorization, own-account and readiness answers with their evidence |
| `SelfMembershipAssessmentSet` | Readback voucher distinguishing no scheduled request from no product |
| `SelfMembershipOperation` | Whether the explicit own-account request adds or removes membership |
| `SelfMembershipIssue` | A missing input or known readiness blocker that limits the answer |
| `SelfMembershipAceEvidence` | One original permission entry beside requester applicability and scope |
| `SelfMembershipDiscoveryBudget` | Explicit work limits for an automatic scan; no production default is chosen |
| `SelfMembershipDiscoveryMode` | Whether questions came from explicit requests or an automatic scan |
| `SelfMembershipDiscoveryReason` | Why coverage is limited, keeping missing evidence, unsupported routes and processing stops apart |
| `SelfMembershipDiscoveryLimitation` | One limitation bound to the captured target, permission, trustee or member it came from |
| `SelfMembershipDiscoveryCoverage` | What the scan examined and where it stopped, never a claim about the forest |
| `SelfMembershipSummary` | Generation-bound counts and coverage read without loading every assessment |

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

### Bounded concrete requester assessment — schema 17

**Implemented from captured evidence; not a new live acceptance result.** Decision `0111` adds an
explicit requester/target/add-or-remove assessment beneath the existing named-holder product. The
first supported authorization routes are a direct captured user grant and one explicit same-domain
global security-group membership. The permission list is evaluated once for the concrete requester,
so an applicable deny through another identity is not missed. Stored order is retained.

Authorization, the own-account restriction and operation readiness are three separate answers. A
disabled account can therefore have established permission evidence without being described as able
to authenticate. An absent captured `member` value remains unknown rather than proving absence.
Nested, primary-group, SID-history, foreign, cross-domain, domain-local, universal and unresolved
routes remain unknown where they could change the permission answer. The assessment describes an
ordinary authenticated directory user; it is not a reconstruction of a live access token or a
prediction that an LDAP operation will succeed.

Judging accepts an explicit, deterministic request batch and refuses a batch beyond its configured
budget rather than silently dropping requests. Schema 17 stores the evidence seal and generation,
request identities, operation, three answers, original permission entries, requester applicability,
typed limits and links to the existing holder edges. Requester assessments are uncounted detail:
the named holder count required by `0097` is unchanged. Empty readback states whether no request was
scheduled or the requester product was not derived. The object-first and requester-first Shell views
read the same stored rows and perform no authorization calculation.

The 2026-09-06 artifacts remain historical evidence of two live grant shapes. They were not changed
or used to promote their schema-16 Unknown rows. Schema-16 judgements must be re-judged to obtain the
new product; evidence and derivation do not need to be rewritten. P-145 remains open.

**Earlier implementation-session validation (recorded, not rerun by the reviewer):**
`SelfMembershipRequesterTests` covers direct and one-global-group grants,
an applicable deny through another requester identity, stored order, missing membership,
distribution groups, another requested member, disabled accounts, incomplete descriptors and the
0x08/0x20 distinction. `JudgingEndToEndTests.ExplicitRequesterSurvivesTheRealCoordinatorWithoutMultiplyingTheHolderEdge`
writes and seals a real synthetic bundle, schedules one request, and reads its original permission
and holder-edge link back. Storage and presentation tests compare both directions. Schema-17 layout
mutations detect an added requester column and a removed identity index. The solution build and all
3,403 tests passed. The 238 historical artifact hashes, two lab-script hashes and fresh Evidence hash
were rechecked unchanged; no directory operation or cleanup ran.

#### Authorization correction and remaining review findings

The bounded authorization evaluator now retains possible earlier allow and deny outcomes instead
of discarding uncertainty when a later matching entry is reached. An uncertain deny before a known
allow, or an uncertain allow before a known deny, yields Unknown. Uncertainty that cannot change
the outcome does not erase a justified answer: a possible deny followed by a known deny remains
NotEstablished, and a possible allow followed by a known allow remains Established. A definite
decision stops evaluation; a later deny does not overturn an earlier grant. An undecided path at
the end of the DACL is implicitly denied, so a possible deny alone cannot grant the requested right.
These expectations follow Microsoft's
[ordered access check](https://learn.microsoft.com/windows/win32/secauthz/how-dacls-control-access-to-an-object),
not a rule that denies always win. Incomplete descriptors cannot justify either definite answer
because the evidence does not locate or constrain the missing entries. Callback conditions are
not evaluated; their possible allow/deny effects are retained. Unrecognized ACE kinds remain
uncertain in both directions.

SELF now resolves the captured holder and SID together to the target object. A real SELF trustee
has no DN; the requester explanation nevertheless identifies the captured target group and its
explicit same-domain global-security membership. The original entry still names `S-1-5-10` (SELF).
Missing target SID/GUID yields IdentityMissing; missing membership stays MembershipNotEstablished,
not non-membership. This does not expand the supported membership routes or equate SELF with the
requester. Add and Remove share authorization for the validated write (`0x08`, not `0x20`), while
own-account and readiness remain separate, including disabled accounts and already-present members.

**Correction validation:** the unchanged focused test selection, `SelfMembershipRequesterTests`
and `JudgingEndToEndTests`, ran 69 cases against the unfixed production code: 39 passed and 30 failed.
After the fix, all 69 passed with none failed or skipped. The full solution build succeeded.
Visual Studio Test Explorer then ran the entire `SecureAD.Next.Tests` project: **3,444 passed,
zero failed and zero skipped**. The focused runs used those two fully qualified TypeName filters;
the full run used the Project filter. These are new executions, not historical test statuses.
The regressions cover both unsafe answer directions, same-outcome and later uncertainty,
incomplete descriptors with relevant entries, callback/unsupported entries, unknown scope/trustees,
bounded unsupported routes and both Add/Remove paths. Four synthetic sealed-bundle cases exercise
the real permission reader and coordinator with null-DN SELF, explicit/absent membership, and
missing target SID or GUID. Historical expected values and retained laboratory Evidence are not
inputs to these new synthetic tests and were not rewritten.

The session-start SHA-256 comparison covered 1,268 tracked/nonignored files: only the two production
files, two test files and two documentation files changed; none were added or removed. All 330
artifact/lab/script files in that comparison, including both retained Self-Membership scripts,
were unchanged. The ignored fresh `evidence.db` was checked separately against the supplied baseline
and still hashes to `137FF0CE603D5CC6463C76D1FA0432245A57C2FC1FF48481BDDDA9C6A8B8DA41`.
This comparison is not a rerun of the historical 238-file fingerprint procedure. The session-only
diff was inspected and `git diff --check` passed. No AD contact, directory operation, cleanup,
application launch, historical fixture change or commit occurred. The pre-existing modification
to `.github/copilot-instructions.md` was left untouched.

**R5 persistence correction:** requester readback now refuses malformed stored answers even when
the judgement seal correctly describes those bytes. Local `System.Text.Json` options require every
non-optional constructor field and respect non-nullable fields. Microsoft's
[required-property guidance](https://learn.microsoft.com/dotnet/standard/serialization/system-text-json/required-properties)
and [nullable-annotation limits](https://learn.microsoft.com/dotnet/standard/serialization/system-text-json/nullable-annotations#limitations)
distinguish missing fields from explicit nulls and explain why root arrays and collection elements
also need explicit checks. This is local to requester persistence, not a global serializer change.

- JSON null, malformed JSON, wrong collection shapes, null elements, missing nested constructor
  fields, null required nested values and null `ApplicationData` are rejected, not replaced by empty
  collections. Enum values must be defined. Original ACE type text is retained, including unknown
  ACE kinds; readback does not turn unsupported captured evidence into a new authorization answer.
- Required scalar text must be nonblank; typed GUIDs and timestamps must parse. SQLite account
  values must be integers and `member_present` must be exactly 0, 1 or null. Assessment and holder
  IDs must be positive, ACE ordinals nonnegative and unique, and holder IDs unique. Assessment
  generation, consumed Derivation generation and Evidence seal must agree with the judgement.
- A missing requester product beside assessment rows is invalid even when the query selects no
  row. An incomplete or unsupported requester product is refused. An absent product with no rows
  still means NotDerived; an empty completed product remains a different, valid answer.
- Each referenced holder edge must exist beneath a completed, supported control product and match
  target DN (case-insensitively), target GUID when known, `CanAddSelfToGroup`, both generations and
  counted state. Its holder SID and resource scope must match at least one stored requester route
  not marked DoesNotMatch; Unknown routes remain possible references, not grants. SELF keeps its
  original `S-1-5-10` explanation and resolves to the assessment target SID for matching. BUILTIN
  identities require the target domain's scope; unscoped identities cannot acquire an extra scope.
- Empty holder lists remain valid without a control product. Explicit nullable identity evidence
  remains nullable. No permissions, readiness or membership answers are recomputed during readback.
  A malformed selected row aborts the whole read rather than exposing the preceding valid rows.
  Data errors become `InvalidDataException` with assessment/field context (and edge ID for a bad
  reference); the Shell adapter returns `Shell.SelfMembershipAssessmentsUnreadable`, not an empty
  success or an unhandled parsing exception.

**R5 validation:** the interrupted tests compiled, but their first run (195 cases: 10 passed,
185 failed) could not open the new synthetic stores because their Derivation generation was
fabricated. That is fixture failure, not persistence evidence. Creating a real sealed synthetic
Derivation reached readback: 195 cases, 15 passed and 180 failed against unchanged production.
The expanded pre-fix selection ran 231 cases: 17 passed and 214 failed. Those raw totals also include
two test defects later corrected: an error-code expectation missing the established `Shell.` prefix,
and a target-mismatch mutation blocked by a foreign key. They are not 214 independently demonstrated
production defects. The latter fixture now creates the alternate control object before redirecting
the edge, without disabling foreign-key enforcement. No frozen historical expected value changed.

After the production correction and these test repairs, `SelfMembershipStorageTests` plus
`ControlEdgeStorageTests` ran **231/231 passed**, covering both directions and the real Shell
adapter. `MalformedSealedRowIsRejectedInBothDirections`,
`ShellReportsMalformedSealedRowsAsReadFailures`,
`HolderReferencesRequireMatchingCompletedControlProduct` and
`BuiltinReferencesRequireTheTargetResourceScope` exercise the refusals; direct/SELF Add and Remove,
explicit missing evidence and empty/unscheduled products supply positive controls. The existing
real-edge round trip in `ControlEdgeStorageTests` was preserved. The R1/R3 selection,
`SelfMembershipRequesterTests` plus `JudgingEndToEndTests`, ran **69/69 passed**. A fresh full
`SecureAD.Next.Tests` run passed **3,665/3,665**, with none skipped, and the full solution build
succeeded. Focused runs used fully qualified TypeName filters; the full run used the Project filter.

The R5 baseline contains 1,269 tracked/nonignored files; a separate read-only hash manifest covers
389 retained artifact/lab files including ignored files. Retained files remained unchanged, including
fresh Evidence SHA-256 `137FF0CE603D5CC6463C76D1FA0432245A57C2FC1FF48481BDDDA9C6A8B8DA41`.
This is not a rerun of the historical fingerprint procedure. No AD contact, application launch,
directory operation, cleanup or commit was performed. Existing instructions and earlier feature
work were preserved. Schema 17, evaluator version 1 and control engine version 2 are unchanged.

| Review finding | Current status |
|---|---|
| R1 — ordered uncertainty | Corrected and regression-tested; definite answers require agreement of the possible ordered outcomes. |
| R2 — no production requester scheduling | Shared automatic discovery, coverage persistence and minimum host notices are implemented in schema 18. Production enablement remains open: Shell/CLI pass no discovery budget pending approval of a numerical recommendation. Completed synthetic measurements are recorded below; they do not enable the feature. |
| R3 — SELF holder resolution | Corrected and regression-tested through the real permission reader/coordinator; original SELF evidence is retained. |
| R4 — stale/mixed-generation Shell rows | Corrected and regression-tested: old rows clear on failed reads/selection changes; differing judgement generations withhold both products. See the [Shell readback contract](../shell/the-assets-screen.md#requester-and-control-readback-safety--r4). |
| R5 — supporting JSON and holder-edge validation | Corrected and regression-tested; malformed records and mismatched references fail the read, including through the Shell adapter. Persistence safety only, not feature acceptance. |
| R6 — requester grid sizing | Corrected and regression-tested after owner approval of the synthetic preview. Real-product laptop/monitor/forest checks remain outstanding; not fully visually accepted. See the [Shell sizing contract](../shell/the-assets-screen.md#requester-sizing--r6). |
| R7 — incomplete requester presentation | Open, deferred to the Shell slice. |
| R8 — contradictory product overview | Immediate historical/evaluator/scheduling distinctions corrected here and in the product overview; final cross-document reconciliation remains open for acceptance. |

The R1/R3 authorization correction, R5 persistence safety and R4 Shell readback safety are complete.
R4's unchanged focused selection passed 47/47 after 18 passed and 29 failed against the unfixed
Shell; its additional regression selection passed 348/348, the full test project passed 3,703/3,703
with none skipped, and the solution build succeeded. The linked Shell document owns the behavior
and test details. No persistence or authorization code changed for R4.

R6 sizing is now corrected without changing authorization, persistence, schema 17 or scheduling.
The unchanged 12-case layout selection passed 12/12 after 6 passed and 6 failed against the unfixed
layout; the broader selection passed 133/133, the full test project passed 3,715/3,715 with none
skipped, and the solution build succeeded. The linked Shell document owns the measurements and
the distinction between the approved synthetic preview and outstanding real-product validation.

This does not accept the whole requester feature, close P-145, or provide a live LDAP-success claim.
**Continue with R2, then R7 and R8 in bounded slices.** The owner clarified that laptop/monitor
checks will happen during normal verification, not in a separate session blocking this work.
They remain unperformed, not implicitly accepted. At the end of the R6 session, ordinary Shell/CLI
re-judging scheduled no requester batch and R2 had not been implemented. The later schema-18
integration described below supplies automatic discovery but leaves it inactive in both hosts
without an approved budget. R2 enablement, R7 presentation and R8 final cross-document acceptance
reconciliation remain open; the historical R6 validation does not accept those later changes.

#### R2 production scheduling boundary

**Contract and integration approved, 2026-09-07; implementation and numerical budget remain
outstanding.** After an explanation tied to the actual production paths below, the owner answered
"i approve proceed". This approves the shared permission-first scheduler, both own-account Add and
Remove per concrete pair, schema-18 persisted discovery summary and typed limitation records,
generation-bound summary/selection readback, and minimum Shell/CLI notices. Authorization and
explicit-batch refusal do not change. No numerical automatic-discovery default is approved; measure
and obtain approval before enabling a new production limit. This later answer supersedes the
earlier coverage-contract approval boundary below, not the outstanding implementation/validation.

##### Delivered in schema 18 — 2026-09-07

**Automatic discovery is implemented and reached by both hosts; it performs no work until a
processing limit is configured, and says so.** `SelfMembershipScheduler` runs inside the existing
single pass over captured objects, so discovery costs no extra read of the bundle. For each captured
group it examines Self-Membership entries that apply to the object itself, resolves the direct user
or the explicit same-domain global-security-group members, resolves `SELF` through the target, and
schedules **both Add and Remove for the requester's own account** on every concrete pair. Missing
membership never selects the operation. `SelfMembershipEvaluator` decides every answer unchanged, so
decision 0111's authorization rules, the own-account constraint and holder counts are untouched.

**Discovery does not restrict itself to established allows.** Denies and uncertain entries are
discovered, because a scan that kept only the safe cases would produce a screen listing exactly what
an administrator does not need. Broad runtime trustees and NULL DACLs are recorded as limitations
rather than expanded into a requester per captured account: expanding them would manufacture
concrete claims the evidence does not support.

`SelfMembershipDiscoveryCoverage` is persisted with the assessments and validated on read. It
records the mode, whether the captured-input scan finished, the configured budget, the work
consumed, the pairs discovered and typed `SelfMembershipDiscoveryLimitation` records. The four
states remain distinct and separately reportable: **missing captured evidence**
(`DescriptorUnavailable`, `MembershipNotCaptured`, `GroupTypeMissing`, `MissingIdentity`),
**unsupported analysis** (`UnsupportedRoute`, `BroadTrustee`, `UnresolvedTrustee`), **processing
stops** (the four budget reasons) and a failed or cancelled attempt, which publishes nothing and
leaves the previous generation current. A finished scan claims only that the captured permissions
this run could read were examined; it is not a claim about the forest or about attribute
completeness. `JudgementReader.ReadSelfMembershipSummary` reads counts and coverage without
materialising every assessment, and the selection read carries the same coverage.
`SelfMembershipCoverageStorage` refuses a missing, malformed, contradictory or orphaned record,
including through the Shell adapter, rather than returning an empty-looking result.

**Both production hosts now report it.** `JudgingLauncher` reads the summary back from the store and
`NewAuditViewModel` states it on the completion screen; `SecureAD.Cli.Program.Summarise` prints the
equivalent line for an unattended run. Each host words its own sentence, following the existing
`UnresolvedWording` precedent, but both read the same stored fields so the facts cannot drift.
**When no budget is configured — the current shipping state — both say the questions were not
scheduled and that this is not a result saying nobody can add themselves to a group.**

Validated offline against synthetic sealed bundles only. `SelfMembershipDiscoveryTests` proves
discovered requests reach judging and persist readable answers through the Shell post-capture path,
CLI `--judge` and CLI post-capture, each observed failing first with zero stored answers.
`SelfMembershipDiscoveryCoverageTests` covers denies, uncaptured permissions, NULL DACLs, broad
trustees, missing group type, unsupported scope, both operations per pair, a deterministic
processing stop that retains what it found, and a cancelled judging leaving the earlier generation
current. `SelfMembershipCoverageTests` mutates the sealed store in twelve ways and requires a
controlled read failure in both directions. `SelfMembershipNoticeTests` checks the host wording.
No AD contact, no application launch, no retained artifact or lab write.

**Still open.** No numerical automatic-discovery budget has been measured or approved, so normal
judging schedules nothing today; that measurement is the next bounded task. Nested, primary-group,
SID-history, foreign-principal and cross-domain routes remain unsupported and are recorded as such.
Broad R7 presentation and R8 reconciliation remain deferred, real-forest verification has not
occurred, and P-145 and R2 remain open.

##### What discovery costs — measured 2026-09-07, no budget set

**Measured with `next/tools/SecureAD.Measure`, offline against synthetic captures only.** Each shape
is judged twice, once with the scan configured and once with no budget, so the difference is the
cost of discovery and nothing else. Figures are from one machine — Xeon 8171M, 8 cores, 32 GB — and
**are not a published safe threshold for any forest**.

| Capture shape | Pairs | Scan cost | Per pair | Stored per pair |
|---|---|---|---|---|
| 1,000 objects | 500 | 0.5 s | 1.06 ms | ~3.1 KB |
| 5,000 objects | 2,500 | 3.7 s | 1.49 ms | ~3.1 KB |
| 10,000 objects | 5,000 | 12.6 s | 2.52 ms | ~3.1 KB |
| 20,000 objects | 10,000 | 54.2 s | 5.42 ms | ~3.1 KB |
| 10,000 objects | 25,000 | 180.9 s | 7.24 ms | ~3.1 KB |

**Storage is stable and predictable at about 3.1 KB per account/group pair.** Elapsed time is not:
the cost per pair climbs as the work grows.

**Two defects were found and fixed, and the answers did not change.** Each question about a group
re-read that group's permissions and re-queried its stored control edges; questions are now ordered
by target so each is read once. And every answer was its own committed transaction — the
control-edge writer already batched, while the requester writer passed no transaction — so 50,000
answers meant 50,000 commits; they now commit in batches of 1,000, rolled back if a run fails part
way. Together these took the largest shape from 211.7 s to 180.9 s and the smallest from 1.1 s to
0.5 s.

**Correction from the laptop measurement: the earlier object-count comparison was invalid.**
Judging's `scan-ms`, `read-ms`, `assess-ms` and `write-ms` remain useful observations, including the
13.4-second scan and 2.7-second request loop. However, the old generator always wrote every member,
holder and target plus the domain root, even when this exceeded the requested object count.
Both the nominal 3,000-object and 9,000-object runs with 750 groups and ten members therefore held
**9,001 objects**. Their similar elapsed times did **not** rule out a table-size or collation cost.
The nominal 10,000-object / 25,000-pair shape in the historical table actually held **27,001 objects**.
The table preserves the recorded figures, not an endorsement of its original shape labels.

**The requested batched read is implemented without narrowing the attributes returned.**
`ObjectAttributesReader.Read` still reads the object row, then reads every multi-valued table in
one `UNION ALL` query with separate text and byte columns. Ordinal order is restored within each
attribute. Empty attributes remain present; `Find` returning null cannot mean unfetched. The
complete-input and independently named regression checks are described in
[what an object holds](../evidence/what-an-object-holds.md).

**A Release baseline was collected before the reader edit on this laptop**, through
`SecureAD.Measurements.ObjectReadBenchmarks.ReadObjectAttributes`. It uses 1,000 generated objects,
100 real by-name reads per invocation, and separate empty/populated cases. Setup and capture
generation are outside the measured method. The same benchmark was used unchanged afterwards.

| Input | Before mean | After mean | Change | Before / after standard deviation |
|---|---|---|---|---|
| Empty attributes | 174.5 µs | 167.4 µs | -4.1% | 16.79 / 9.70 µs |
| Populated attributes | 129.3 µs | 130.5 µs | +0.9% | 4.15 / 4.09 µs |

**No meaningful speedup is established.** These are short-run measurements with substantial
uncertainty, not evidence for a processing budget. An initial union-wide database sort regressed
the populated case to 170.1 µs; that version was replaced with per-attribute ordinal sorting before
the after measurement above. The baseline CPU trace attributed 7.09% total samples to SQLite's
parameterless `ExecuteReader`, including calls from both object and value reads. Later sampled
symbol attribution was inconsistent, so no new dominant-cause claim is made from those names.

**The harness now verifies what is stored, not what was requested.** Impossible shapes are refused;
object, domain and physical ACE counts are read independently from the generated database before
judging. Each configured scan must finish, discover exactly the generated number of pairs and store
two assessments per pair; the scan-off run must store none. The name-lookup query plan on the new
synthetic captures reports `SCAN captured_object USING COVERING INDEX ix_captured_object_dn`, not
an indexed name seek. This is a remaining measured investigation, not permission to change sealed
storage, collation semantics or the host budget.

**Completed volume run on this laptop: Intel Core i7-1370P, 14 cores / 20 logical processors,
about 32 GB RAM, .NET 10.0.11, Release.** The 0.1-scale capture was independently verified as
34,700 objects, 590,000 physical ACEs and nine domains, with mean DN length 92.4 characters.
Generation took 20.6 seconds; the sealed capture occupied 231 MB. All three scan-on runs completed
with 750 discovered pairs and 1,500 assessments; every scan-off run stored none.

| Repeat | Scan off | Scan on | Difference | Scan-on allocated bytes | Added judgement bytes |
|---|---|---|---|---|---|
| 1 | 72,601.7 ms | 64,448.7 ms | -8,153.0 ms | 4,910,620,072 | 3,768,320 |
| 2 | 51,852.5 ms | 66,492.6 ms | 14,640.1 ms | 4,909,675,968 | 3,768,320 |
| 3 | 78,729.0 ms | 86,858.2 ms | 8,129.3 ms | 4,909,654,888 | 3,768,320 |

The median paired difference is 8,129.3 ms, but the spread and negative first difference prevent
interpreting that as a reliable isolated discovery cost. Allocated bytes are cumulative allocation,
not peak memory. Judgement storage was 12,836,864 bytes with scanning versus 9,068,544 without.
The final run's phase log recorded scan 6,214 ms, read 354 ms, assess 578 ms and write 111 ms.
The raw CSV remains in the system temporary directory under
`SecureAD-measure-20260907-071634-0786180ac66b46f7b253a973ac03e6a3/measurements.csv`;
the generated capture was deleted after the repetitions. A small nine-domain validation run also
verified 1,000 objects / 17,000 ACEs / 90 pairs, and the old impossible
`1 3000 750 10` command was observed failing before generation.

**Full-volume run completed successfully on 2026-09-07; one observation, not a budget acceptance.**
`1 --production 1` generated and independently verified **347,000 stored objects / 5,900,000
physical ACEs / nine domains**, with mean DN length 93.4 characters. Generation took 197.7 seconds
and the sealed capture occupied 2,341 MB. The harness exited with code 0. Scanning completed with
exactly **7,500 discovered pairs and 15,000 stored assessments**; the scan-off run stored none.

| Full-volume metric | Observed value |
|---|---|
| Judging with discovery off | 4,713,081.4 ms — 78 min 33 sec |
| Judging with discovery on | 5,002,759.3 ms — 83 min 23 sec |
| Paired elapsed difference, as recorded in CSV | 289,678.0 ms — 4 min 50 sec |
| Scan-on cumulative allocated bytes | 49,104,321,136 |
| Judgement bytes with discovery off | 89,944,064 |
| Judgement bytes with discovery on | 127,713,280 |
| Additional judgement bytes | 37,769,216 |
| Scan completed / pairs / assessments | True / 7,500 / 15,000 |

The final phase log recorded `scan-ms=338507`, `read-ms=18704`, `assess-ms=30886` and
`write-ms=806`. Those phase times are measurements inside the scan-on run, not components that
must sum to the difference between two separate whole runs. The allocation figure is cumulative
managed allocation, **not peak memory or a required RAM capacity**. The CSV is retained beneath
the system temporary directory at
`SecureAD-measure-20260907-072851-5bd6899deaab4779986b8f83f2a80016/measurements.csv`.

**The next investigation is the scan-off judging pipeline.** It already took nearly 79 minutes,
with no requester discovery and with the harness scheduling **zero rules**. That time must not be
attributed to the product's 17 rules, nor assumed to be explained by requester name lookups. Profile
the real scan-off path on bounded, independently verified synthetic shapes, separating evidence
streaming and permission reads, control-edge derivation, store writes and sealing. Vary object and
ACE counts separately to identify which work grows, then change only a measured bottleneck and
repeat the same measurement. The name-predicate index scan remains a lead, not a proven explanation
of this baseline. No new full-volume run or production-code change is implied by recording this plan.

**Bounded scan-off CPU profile completed, 2026-09-07.** The new
`next/BenchmarkSuite1/ScanOffJudgingBenchmarks.cs` calls the actual `JudgingRun.Judge` with zero
rules and a null discovery budget. Its four shapes vary objects and physical ACEs independently,
retain nine domains and 18 target/holder group pairs with five members each, and use the same
distinct synthetic read-property trustees as the volume harness. Capture generation and stored-count
verification are outside the measured method. Independent SQL counts are checked against requested
objects, domains and ACEs; three deliberately wrong expected counts are observed being rejected.
Each measured judgement must complete; readback checks zero requester pairs and assessments.
The fixture is deleted afterwards. The existing object-read benchmark and production code were not
changed. The new benchmark is frozen after its successful run.

Release BenchmarkDotNet monitoring job: one launch, one warmup, three measured iterations, one
invocation per iteration. CPU trace session: `de9f9690-2482-4f91-8976-add999cd4b56`.

| Objects | Physical ACEs | Mean | Reported error | Standard deviation |
|---|---|---|---|---|
| 1,000 | 17,000 | 329.6 ms | 1,011.7 ms | 55.46 ms |
| 1,000 | 51,000 | 528.8 ms | 1,602.2 ms | 87.82 ms |
| 3,000 | 17,000 | 707.2 ms | 2,037.4 ms | 111.68 ms |
| 3,000 | 51,000 | 929.0 ms | 2,071.1 ms | 113.52 ms |

Both object count and ACE count affect the observed means, but the short-run uncertainty is large.
These timings neither establish a scaling law nor explain the 79-minute full-volume baseline.
They are new workload measurements, not before/after optimization results.

| Reported sampled function | Self CPU | Total CPU |
|---|---|---|
| `PrincipalClassificationRegistry.For` | 0.06% | 29.64% |
| `SqliteCommand.ExecuteReader(CommandBehavior)` | 13.10% | 13.11% |
| `ObjectPermissionsReader.DescriptorOf` | 0.04% | 3.92% |
| `ObjectPermissionsReader.ObjectOf` | 0.00% | 3.05% |
| `ObjectPermissionsReader.Lookup` | 0.03% | 1.79% |

**Attribution limits matter.** These are sampled CPU percentages, not elapsed phase timings, and
the trace also includes fixture setup and readback. Its call tree contains implausible getter/runner
ancestry, while the reported classification hotspot has no line-level samples. Treat that
classification attribution as provisional; do not change authority classifications or claim that
classification explains 29.64% of the full-volume elapsed time.

The more concrete source-mapped observations are in `ObjectPermissions.cs`: line 381, the by-name
object query's `ExecuteReader`, carries 204 samples (2.96% of trace samples); line 644, the trustee
lookup's `ExecuteReader`, carries 94 (1.36%). The object query uses
`WHERE distinguished_name = $dn COLLATE NOCASE LIMIT 1`. Source inspection confirms that
`JudgingRun.cs` line 394 calls `ReadPermissions(subject.DistinguishedName)` inside the whole-object
loop even with discovery off and no rules. This places the previously observed name-predicate scan
on the scan-off path too; it still does not quantify its full-volume share.

**Permission-name query isolated, 2026-09-07: the repeated scan is now reproduced directly.**
This follows the earlier repeated-read finding rather than reopening it. The batched attribute
read was implemented, but it did not remove the separate permission reader's object-name lookup.
The existing CPU trace was reused; no duplicate pipeline benchmark or full-volume run was started.

The check loaded the product's Release SQLite provider (SQLite **3.53.3**) and called the actual
`BundleSchema.CreateTables` and `BundleSchema.CreateDeferredIndexes` in disposable in-memory
databases. Only synthetic `captured_object` rows were inserted, with verified inserted counts.
Foreign keys were disabled for this isolated table fixture: it is **not a sealed capture or an
end-to-end judging measurement**. No evidence file, production schema, host or protected artifact
was changed. The SQL tested was the exact `ObjectPermissionsReader.ObjectOf` query:

```sql
SELECT object_id, distinguished_name FROM captured_object
WHERE distinguished_name = $dn COLLATE NOCASE LIMIT 1
```

`PRAGMA index_xinfo(ix_captured_object_dn)` reports **BINARY** collation on `distinguished_name`.
`EXPLAIN QUERY PLAN` reports:

| Query | Observed plan |
|---|---|
| Actual permission-name query, `COLLATE NOCASE` | `SCAN captured_object USING COVERING INDEX ix_captured_object_dn` |
| Case-sensitive diagnostic control | `SEARCH captured_object USING COVERING INDEX ix_captured_object_dn (distinguished_name=?)` |
| Integer object-ID diagnostic control | `SEARCH captured_object USING INTEGER PRIMARY KEY (rowid=?)` |

The index exists, but its name comparison does not match the query's case-insensitive comparison.
This makes the actual query scan the index rather than seek to a name. **Removing `NOCASE` is not
a fix:** the diagnostic control returned no object for the deliberately case-varied name, while
the real query returned the correct object. First, middle, last, case-varied and absent probes
were all checked for their expected returned object ID or absence.

Native `sqlite3_stmt_status` counters measured work rather than laptop-dependent timings:
`SQLITE_STMTSTATUS_FULLSCAN_STEP` (1) counts forward scan steps; `SQLITE_STMTSTATUS_VM_STEP` (4)
counts executed SQLite virtual-machine instructions. The numbers below are observed counters,
not elapsed-time estimates and not ambiguous profiler symbol attribution.

| Rows | Last-name scan steps | Last-name VM steps | Absent-name scan steps | Absent-name VM steps |
|---|---|---|---|---|
| 1,000 | 999 | 3,011 | 999 | 3,008 |
| 3,000 | 2,999 | 9,011 | 2,999 | 9,008 |
| 10,000 | 9,999 | 30,011 | 9,999 | 30,008 |

Case-varied last-name probes had exactly the same work as the last-name probes. The first-name
probe used zero scan steps and 14 VM steps at all sizes, demonstrating why early-object probes
alone miss the growth. The case-sensitive control used zero scan steps and 14 VM steps for each
existing exact-case name at all sizes; absent and case-varied probes used 10 VM steps and returned
nothing. That control isolates the collation mismatch but intentionally does **not** preserve the
production behavior, so it is not an optimization candidate as written.

The exact production query was then executed once for **every** name in each synthetic table;
each result was checked against its expected object ID. A prepared statement was reused, so these
counts exclude repeated statement preparation and do not time the complete permission reader.

| Rows / successful lookups | Observed total scan steps | Observed total VM steps |
|---|---|---|
| 1,000 | 499,500 | 1,512,500 |
| 3,000 | 4,498,500 | 13,537,500 |
| 10,000 | 49,995,000 | 150,125,000 |

The total scan work matches `N * (N - 1) / 2`: ten times as many objects produced about one hundred
times as many scan steps in this isolated all-object lookup. **This establishes a concrete
quadratic lookup mechanism on the scan-off path, not the fraction of the 79-minute run it caused.**

**The bounded permission-read fix is implemented and remeasured, 2026-09-07.** The Evidence reader
retains the most recently streamed object's internal row ID and exact name. An exact-name permission
read uses that ID directly, passing through the unchanged descriptor parsing, trustee resolution
and uncertainty logic. No public method signature, object-attribute contract or sealed schema changed.

**Ambiguity is checked, not assumed away.** Once per reader, before the fast route is used, SQLite
groups stored names under its own `NOCASE` comparison and checks for duplicates. That adds one
name-index scan/sort, not one name scan per object. If any names are ambiguous, the entire reader
keeps the original lookup. Case-varied and non-current names likewise retain the original lookup.
This is one retained identity and one boolean, not a managed dictionary of the forest. The internal
row ID avoids treating null or repeated GUIDs as interchangeable objects. The owning description is
[what an object's permissions hold](../evidence/what-an-objects-permissions-hold.md).

Five new regression cases passed against the old reader before the change and the same 40
permission tests passed afterwards. They exercise null and shared GUIDs, duplicate names with exact
or different case, non-ASCII case distinctions, escaped commas, earlier/missing objects, absent
descriptors and disposal. Duplicate-name reads are compared with a separate, non-streaming reader
using the original lookup, so bypassing the ambiguity guard would select a different descriptor and
fail the comparison. No frozen fixture or existing benchmark was changed.

The **same** `ScanOffJudgingBenchmarks.JudgeWithoutDiscovery` CPU collection and four parameter
combinations were rerun unchanged. Before session: `de9f9690-2482-4f91-8976-add999cd4b56`;
final after session: `d56c86d9-c201-493d-9fb3-ebc721aef546`. The pre-change figures below are the previously
recorded baseline, not another newly generated estimate.

| Objects | ACEs | Before mean | After mean | Mean change | Before / after error | Before / after standard deviation |
|---|---|---|---|---|---|---|
| 1,000 | 17,000 | 329.6 ms | 431.4 ms | +30.9% | 1,011.7 / 2,980.5 ms | 55.46 / 163.37 ms |
| 1,000 | 51,000 | 528.8 ms | 511.0 ms | -3.4% | 1,602.2 / 1,701.3 ms | 87.82 / 93.25 ms |
| 3,000 | 17,000 | 707.2 ms | 556.9 ms | -21.3% | 2,037.4 / 1,795.0 ms | 111.68 / 98.39 ms |
| 3,000 | 51,000 | 929.0 ms | 741.4 ms | -20.2% | 2,071.1 / 1,858.6 ms | 113.52 / 101.88 ms |

The larger bounded shapes have lower observed means; **the smallest regressed by 30.9% in the final
run**, with high variance. The first after run (`d98f4649-bdca-43f8-a6e0-f1e487e3034a`) recorded means
335.3 / 523.6 / 545.2 / 770.6 ms in the same row order. The full test suite then caught an optional
null callback default; the callback was made an explicit required collaborator, without changing
the gate, and the complete benchmark was rerun on that final code. Both observations are retained
rather than selecting the more favorable small-case number. **The wide short-run uncertainty
prevents calling these percentages established speedups or dismissing the regression.** The new
traces contain the `ReadAt` route; the initial after trace also identifies the once-per-reader
uniqueness check. Sampling metadata and call attribution vary, so CPU percentage changes are not
used as an improvement metric or as proof of the remaining bottleneck. The deterministic change is removal
of repeated name scans for the ordinary unique-name streamed path; ambiguous and arbitrary by-name
reads intentionally retain their old cost.

At completion of the bounded benchmark, no full-volume rerun had been launched. The recorded
78/83-minute observations above remain the **pre-fix baseline**; the subsequent intermediate and
full-volume comparisons are recorded below. No processing budget is approved.

**Intermediate-scale remeasurement completed, 2026-09-07.** The unchanged Release harness was run
with `3 --production 0.1`, the same settings as the earlier intermediate baseline. It regenerated
and independently verified **34,700 objects, 590,000 physical ACEs and nine domains**, with 75
target/holder group pairs, ten members per holder and mean DN length 92.4 characters. This uses
the same synthetic generator and shape, not the earlier deleted capture file. Generation took
23.5 seconds (previously 20.6); the sealed capture again occupied 231 MB.

All three scan-on runs completed with exactly **750 pairs and 1,500 assessments**, and the scan-off
runs stored none. The process exited with code 0 and deleted its generated capture. No production
code or measurement setup changed during this remeasurement.

| Repeat | Scan off | Scan on | Paired difference | Scan-on allocated bytes | Added judgement bytes |
|---|---|---|---|---|---|
| 1 | 14,972.3 ms | 18,796.8 ms | 3,824.5 ms | 4,866,962,096 | 3,768,320 |
| 2 | 11,861.9 ms | 19,131.7 ms | 7,269.9 ms | 4,865,886,552 | 3,768,320 |
| 3 | 12,475.0 ms | 20,630.4 ms | 8,155.4 ms | 4,865,886,872 | 3,768,320 |

**Comparison with the recorded pre-fix intermediate baseline**, using the median of each metric's
three observations. Elapsed differences are medians of paired differences, not the difference of
the two elapsed medians. CSV values retain their own rounding.

| Metric | Before median | After median | Change |
|---|---|---|---|
| Scan-off judging | 72,601.7 ms | 12,475.0 ms | -60,126.7 ms; **-82.82%** |
| Scan-on judging | 66,492.6 ms | 19,131.7 ms | -47,360.9 ms; **-71.23%** |
| Paired scan-on minus scan-off | 8,129.3 ms | 7,269.9 ms | -859.4 ms; -10.57% |
| Scan-on cumulative allocated bytes | 4,909,675,968 | 4,865,886,872 | -43,789,096; -0.89% |
| Judgement bytes with scanning | 12,836,864 | 12,836,864 | unchanged |
| Judgement bytes without scanning | 9,068,544 | 9,068,544 | unchanged |
| Added judgement bytes | 3,768,320 | 3,768,320 | unchanged |
| Scan-on pairs / assessments | 750 / 1,500 | 750 / 1,500 | unchanged |

Every new scan-off time is below every old scan-off time; the same holds for scan-on times. This
is clear observed improvement **at this verified intermediate shape**, unlike the noisy small
benchmark comparison. It does not erase the recorded smallest-case regression or establish a
general speedup for arbitrary by-name/ambiguous reads. Added storage and result counts are equal;
those facts alone are not a comparison of every judgement field across regenerated captures.

The final phase log recorded `scan-ms=5881`, `read-ms=450`, `assess-ms=751`, `write-ms=284`
(the preceding repetition: 5782 / 335 / 540 / 114 ms). Discovery still has separate work; its paired
elapsed differences remain variable and must not be treated as a safe budget. Allocation is
cumulative, not peak memory. The raw after CSV remains under the system temporary directory at
`SecureAD-measure-20260907-163634-064bd62b59c449cabb31ff5b2175c13c/measurements.csv`;
the before CSV is the previously recorded `SecureAD-measure-20260907-071634-0786180ac66b46f7b253a973ac03e6a3` run.

**Post-fix full-volume measurement completed successfully, 2026-09-07.** The owner requested the
run after reviewing the intermediate improvement. The unchanged Release harness ran
`1 --production 1`, regenerating and independently verifying **347,000 stored objects, 5,900,000
physical ACEs and nine domains**, with mean DN length 93.4 characters. It exited with code 0.
The scan completed with exactly **7,500 pairs / 15,000 assessments**; the scan-off run stored none.
The before and after CSVs agree on objects, groups, members per group, domains, ACEs, repetition
count, scan completion and requester counts. These are matching synthetic shapes, not the same
sealed capture file: each run generated its own input and deleted it afterwards.

| Full-volume metric | Before fix | After fix | Change |
|---|---|---|---|
| Judging with discovery off | 4,713,081.4 ms (78 min 33 sec) | 111,315.8 ms (1 min 51 sec) | -4,601,765.6 ms; **-97.64%** |
| Judging with discovery on | 5,002,759.3 ms (83 min 23 sec) | 491,347.0 ms (8 min 11 sec) | -4,511,412.3 ms; **-90.18%** |
| Paired discovery-on minus discovery-off | 289,678.0 ms (4 min 50 sec) | 380,031.2 ms (6 min 20 sec) | **+90,353.2 ms; +31.19%** |
| Scan-on cumulative allocated bytes | 49,104,321,136 | 48,666,289,792 | -438,031,344; -0.89% |
| Judgement bytes with discovery on | 127,713,280 | 127,713,280 | unchanged |
| Judgement bytes with discovery off | 89,944,064 | 89,944,064 | unchanged |
| Additional judgement bytes | 37,769,216 | 37,769,216 | unchanged |
| Scan-on completed / pairs / assessments | True / 7,500 / 15,000 | True / 7,500 / 15,000 | unchanged |
| Capture generation, outside judging | 197.7 sec | 217.8 sec | +20.1 sec |
| Sealed capture size, as reported | 2,341 MB | 2,341 MB | unchanged |

The final scan-on phase log is retained separately from whole-run subtraction:

| Phase log field | Before | After | Change |
|---|---|---|---|
| `scan-ms` | 338,507 | 355,766 | +17,259 ms |
| `read-ms` | 18,704 | 20,078 | +1,374 ms |
| `assess-ms` | 30,886 | 32,900 | +2,014 ms |
| `write-ms` | 806 | 832 | +26 ms |

**The common judging pipeline is substantially faster in this observed full-volume comparison;
the discovery work is not.** Its paired elapsed difference increased by 90.4 seconds and all four
recorded discovery-phase values increased. These regressions remain visible alongside the overall
improvement. A phase measurement within one run is not a component guaranteed to sum to the
difference between two whole runs. The remaining discovery cost is separate from the permission
identity-reuse fix and must not be hidden by its benefit.

Allocation is cumulative managed allocation, **not peak memory or a RAM requirement**. Equal
counts and file sizes do not compare every judgement field across independently regenerated
captures; the separate regression suite supplies the identity/case/absence correctness checks.
Neither the earlier smallest-case regression nor uncertainty is erased by this full-volume result.

Raw CSVs remain beneath the system temporary directory:
- Before: `SecureAD-measure-20260907-072851-5bd6899deaab4779986b8f83f2a80016/measurements.csv`.
- After: `SecureAD-measure-20260907-164746-70cc99867d12454192f04e6e0742634d/measurements.csv`.

Both hosts still pass no budget; recording this comparison changes no production code, storage/schema
or authority decision. SID-classification attribution remains provisional.

**Owner-approved handoff: pause further discovery tuning and return to product work.** Preserve
the validated permission-read fix, regression tests and existing measurement artifacts. The remaining
discovery cost stays open under P-152; pausing tuning does not approve a budget or enable either host.
Remeasure when subsequent work changes data access, candidate counts or processing volume, and before
approving production limits, rather than after presentation-only changes. The owner subsequently
requested a documentation checkpoint, commit and push before moving to a new session; that commit
and push are explicitly authorized. The next bounded preparation is the
[R7 presentation proposal](../shell/the-assets-screen.md#r7-next-bounded-presentation-proposal--awaiting-owner-approval),
which requires explicit approval of the presentation before implementation. R2 enablement and final
R8 acceptance remain open, and laptop/monitor checks remain normal outstanding product verification.

Each full-volume measurement had one repetition, always scan-off before scan-on, supplying neither a variability estimate nor a
stable isolated discovery cost. This completes the observed full-volume before/after comparison, **not**
performance acceptance, a stable scaling curve or a processing-budget proposal. Both hosts remain
unchanged with no discovery budget, and storage/schema and authorization changes remain unapproved.

The solution build and all 3,754 tests passed with zero skipped after the reader, regression-test,
harness and governing-document changes. This is correctness validation, not performance acceptance.

After the bounded permission-read fix and required-callback correction, the full suite passed
**3,759/3,759, zero skipped**. The five new cases account for the increase. The benchmark remained
unchanged and its final after run completed successfully; correctness validation does not close
the outstanding performance acceptance or justify a budget.

**The historical figures are not a bound.** Their requested shapes stopped at 20,000 objects
against a production forest of roughly 347,000 with 5.9 million access control entries — see
[the forest this is built for](../../WHAT-THE-PRODUCT-IS.md#the-forest-this-is-built-for). A budget
argued from them alone would be argued from a capture two orders of magnitude too small.

**To re-run the measurement**, from the repository root:

```powershell
dotnet run --project next/tools/SecureAD.Measure -c Release -- 3
dotnet run --project next/tools/SecureAD.Measure -c Release -- 3 9001 750 10
dotnet run --project next/tools/SecureAD.Measure -c Release -- 3 --production 0.1
dotnet run --project next/tools/SecureAD.Measure -c Release -- 3 --production 1
```

The first argument is how many times each shape is repeated; the next three — objects, groups,
members per group — select a single shape. Two optional following arguments specify domains and
ACEs. `--production` scales 347,000 objects and 5.9 million physical ACEs while retaining nine
domains; the synthetic workload uses 750 target groups with ten members per holder at full scale.
This is volume evidence, **not a reconstruction of production membership density, delegation,
control-edge counts or chained paths**. Additional ACEs are ordinary read-property entries and
have distinct synthetic trustees. Long DNs model naming depth, not a complete OU hierarchy.
**Build in Release or the numbers mean nothing.** Each capture is generated once, reused for all
scan-on/off repetitions, then deleted. Only one capture is needed at a time. `measurements.csv`
remains beneath the printed temporary directory. Scan-on minus scan-off can be negative due to
warmup and noise; never interpret that as a saving or a safe threshold. It contacts no directory
and reads nothing from a real forest. Both production hosts still pass no discovery budget.

The production
Shell path is `NewAuditViewModel.JudgeAsync` through `IJudgingLauncher.RunAsync` and
`JudgingLauncher` to `JudgingRun.Judge`. Its only current launcher caller follows capture; an
interactive offline requester action is not already present. CLI `Program.RunAsync` reaches
`Program.Judge` both for offline `--judge` and after capture/derivation. Both hosts call the overload
that supplies an empty requester list. The CLI does judge; the missing integration is explicit
requester scheduling, not judging as a whole.

The existing request contract carries requester DN, target DN, Add or Remove, and an optional
member DN; null means the requester's own account. The default budget permits **100 submitted
requests** and **10,000 relevant permission entries per assessment**. The coordinator checks the
submitted count before deduplication, refuses an oversized batch rather than taking its first
100 entries, then deduplicates and orders requests deterministically. The permission-entry limit
instead records `PermissionBudgetExceeded` with Unknown authorization. It is not a global bound
on the ordinary rules or control-edge pass. Unknown requester answers are not reflected in the
coordinator's overall completion state, which depends on capture scope and rule outcomes; a host
must read and report requester outcomes separately rather than imply that completion means every
requested question was answered definitively.

Each successful judging publishes a new complete judgement generation, including its entire
requester set. Requests are not automatically carried forward: an empty batch publishes an empty
completed requester product. Failure before publication leaves the previous generation current;
it must not be presented as results of the failed attempt. Evidence and Derivation are not rewritten.
`ExplicitRequesterSurvivesTheRealCoordinatorWithoutMultiplyingTheHolderEdge` exercises the library
coordinator, not either production host. Closing R2 requires host-to-store regression checks that
prove automatically discovered requests reach judging after capture and through offline CLI judging,
then read the persisted answers, including refusal and replacement behavior. Scheduling does not
authorize changing the evaluator, public contracts or storage semantics without prior approval.

**Owner requirement and specification-backed direction:** the owner clarified on 2026-09-06 that
this "should always run on new captures". The existing-capture-first scope and same-Evidence-only
request-file proposal were not approved and are withdrawn. The judgement specification's
[permission/group-first approach](../specs/JUDGEMENT-HALF.md#authorization-membership-is-cached-by-context-capability-evaluation-remains-target-specific)
starts with a captured permission's trustee, resolves relevant captured members and validates scope.
Decision 0111 requires concrete bounded questions, not an administrator-maintained selection list.
Normal Shell and unattended CLI judging must discover them from each capture's own evidence,
including the first capture, within the supported direct-user and single explicit same-domain
global-security-group routes. SELF resolves to the captured target identity and membership, not the
machine's current user. This assesses own-account changes; it never performs membership changes,
uses live lookups or constructs a forest-wide requester/target cross-product.

**Remaining approval boundary:** define and persist truthful discovery coverage and budget stops,
separately from individual authorization answers and overall rule completion. Schema 17's requester
product stores only evaluator version and completion; its public assessment set carries rows,
product availability and generation, not discovery coverage. Unknown assessments require concrete
requests and cannot stand in for an unidentified requester or an unvisited part of the capture.
Decision 0102 requires retained partial expansion with an explicit stop reason; it does not change
the existing submitted-batch refusal into "take the first 100". A new discovery coverage contract,
its storage/readback and the minimum host notices needed to avoid a complete-looking partial result
require approval before implementation. Authorization and holder counts remain unchanged; broad
R7 presentation and R8 reconciliation remain deferred.

**Recommended bounded production slice; not yet approved:** integrate one permission-first scheduler
into normal judging, reached by both hosts. For each relevant captured Self-Membership entry, use
its direct user or explicit group members; resolve SELF through the target. Do not restrict seeds
to established allows: relevant denies and uncertain entries must not disappear from discovery.
Schedule both Add and Remove for each concrete pair, with null member DN, independently of whether
the captured target lists the requester. Missing membership is not proof of absence. Evaluate with
the existing ordered authorization code and retain links to stored holder edges without adding
counted edges. Do not traverse nested/primary-group/SID-history/foreign or cross-domain routes;
record unresolved and unsupported discovery evidence rather than manufacturing requester identities.
Broad runtime trustees and null/unreadable descriptors cannot justify a fabricated complete empty
requester set; record the coverage limitation without expanding every user against those targets.

Use a separate automatic-discovery budget and persisted coverage product, not silent truncation of
submitted batches. **The initial 100-record/50-pair discovery recommendation is withdrawn.** After
the revised recommendation to establish a measured processing budget rather than a blanket 50-pair
cutoff, the owner answered "ok i apporove your proposal". This approves the budget direction, not a
new numerical threshold or the entire proposed storage/readback extension. The explicit library
batch limit is not evidence of an appropriate automatic-discovery limit. The next bounded task is
offline measurement with synthetic inputs: account for discovery work, assessment processing,
memory and stored-result size before recommending numerical limits. Do not bypass the existing
submitted-batch refusal to perform that measurement or contact AD; retained Evidence and laboratory
artifacts remain read-only.

**Budget-direction documentation validation:** the fresh external baseline is
`%TEMP%\SecureAD-R2-budget-baseline-20260906-230510`. The full test project passed 3,715/3,715,
none skipped, and the solution build passed after recording this direction. Only this document
and the product overview were edited; no production code or tests changed. These are preservation
checks, not processing measurements or acceptance of automatic scheduling. No numerical budget
has been established by these test results.

The proposed coverage behavior retains unresolved nodes already encountered and records which
target/holder was reached and the stop reason; an unknown remainder is not a known total. Missing
captured evidence, unsupported analysis and a processing stop are different reasons, not a single
claim of incomplete capture. The 10,000-entry per-assessment authorization limit and explicit
submitted-batch refusal remain unchanged. Ordinary rules and counted holder edges continue
independently. A completed generation may contain a truthfully partial requester product; failure
or cancellation before publication still leaves the previous generation current, never relabelled
as the new attempt's results.

This recommendation needs a versioned judgement-storage/readback extension for discovery scope,
configured limits, unresolved inputs and stop reasons (not changes to Evidence or Derivation), plus
minimum Shell/CLI coverage notices. Historical schema-17 results must not acquire an invented
automatic-discovery coverage claim. Full requester presentation remains R7. Production acceptance
must exercise the real Shell post-capture path and both CLI judging paths using synthetic sealed
bundles, with no directory contact, and prove persisted results and generation replacement rather
than merely inspecting calls or supplying a hard-coded library batch.

**Prerequisite correction validation, 2026-09-06:** the fresh external baseline is
`%TEMP%\SecureAD-R2-baseline-20260906-201531`, at HEAD
`0e4762baf1c713f9bc86538da3e7ab1cde33ed52` on `main`: 30 modified tracked files, 338 untracked,
nothing staged. Only this document and the product overview changed in this prerequisite slice;
no production code or tests changed. Fresh Test Explorer runs passed 526/526 focused requester,
storage, readback, sizing and host regressions and 3,715/3,715 full-project tests, none skipped;
the full solution build passed. These are preservation checks, not R2 before/after defect evidence
or host-to-store acceptance of automatic discovery, which remains unimplemented pending approval.
The session-only diff was inspected and `git diff --check` passed. All 389 retained artifact/lab
files, including ignored files, matched the fresh hash manifest; fresh Evidence remains SHA-256
`137FF0CE603D5CC6463C76D1FA0432245A57C2FC1FF48481BDDDA9C6A8B8DA41`.
Instructions, the gallery, historical fixtures and earlier fixes were preserved. No visual/live
verification, application launch, directory operation, cleanup or commit occurred. R2, R7, R8 and
P-145 remain open.

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
