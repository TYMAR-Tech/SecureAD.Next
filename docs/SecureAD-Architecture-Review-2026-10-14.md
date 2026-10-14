# SecureAD.Next production-scale architecture and performance review

**Date:** 2026-10-14

**Reviewer:** Microsoft Scout / GitHub Copilot CLI, powered by GPT-6.1 Sol

**Purpose:** Independent architectural assessment for comparison with a separate GitHub Copilot review

**Status:** Review and recommendations only; not implementation authorization
**Required technologies:** WPF and SQLite

## 1. Executive assessment

SecureAD.Next is repairable within its existing WPF and SQLite technology constraints. The review does not establish a need to replace the application wholesale, replace the UI framework, introduce a database server, or deploy agents.

The most important architectural issue is the boundary between bulk data and interactive consumption. Screens asking for a small number of saved answers can still open, verify, query, or reconstruct large evidence, derivation, and proof products. Splitting database files helps only if the complete screen stops depending on the heavy products.

There is a separate analysis-throughput problem. Judging works over tens of millions of ACL positions, millions of candidate considerations, hundreds of thousands of requester questions, and substantial graph/proof structures. The finding count is a poor measure of that workload. Existing batching, descriptor reuse, and proof sharing are useful but do not eliminate occurrence-scale computation or question/witness fan-out.

The recommended order is:

1. Complete a bounded responsive-saved-results correction, beginning with the real Dashboard and Findings screen paths.
2. Improve indexed paging, search, page-local retrieval, and WPF data materialization.
3. Redesign selected expensive judgement and derivation products around reusable compact graphs, prepared assessments, and shared proof references.
4. Improve capture throughput, SYSVOL concurrency, consolidation, and recovery separately.
5. Consider incremental cross-run reuse only after dependency invalidation and evidence semantics are designed.

The first two items are the immediate usability project. They should not depend on completing the larger analysis or capture redesign.

**Do not interpret this report as a recommendation for one large rewrite.** The safest path is to preserve working semantic machinery, correct the serving boundary first, and replace internal products in independently reversible steps.

### What this report does not claim

This report does not establish current-candidate production timings, a guaranteed speedup factor, a firm delivery schedule, or production acceptance. It does not establish that every suspected cost is responsible for the observed delays. It is not a security-vulnerability audit or an assessment of every rule's correctness.

## 2. Scope, baseline, and evidence discipline

### 2.1 Reviewed repository state

The requested application directory was:

`C:\Users\jistrand\source\repos\SecureAD.Next\next`

The Git repository root is its parent:

`C:\Users\jistrand\source\repos\SecureAD.Next`

The reviewed branch was `perf02/responsive-browsing`, with HEAD:

`7b922ad01863c22fb614abbcc868a6e70ab6c3c4`

The review included substantial existing uncommitted changes, including the schema-17 captured-navigation foundation and schema-72 segmented Judgement candidate. HEAD alone therefore does not reproduce the reviewed implementation. A second reviewer must examine the working tree and its untracked files, not merely the committed revision.

The existing changes included `NavigationStorage.cs`, `StoreRootManifest.cs`, `JudgementStoreLayout.cs`, changed readers/writers/publication code, and associated tests. They were not reverted, rewritten, committed, or adopted by this review.

The application scope contains seven production projects and approximately 624 C#/XAML files, excluding generated build directories. The investigation followed orchestration, storage, graph, proof, reader, and presentation paths; it was not a claim to inspect every line or independently verify every rule.

### 2.2 Method

The main review traced integrity, publication, navigation, queries, selected-run services, and WPF presentation. Separate review threads investigated capture, derivation, and judgement, with integration notes reconciling shared contracts. Those threads form one review, not three independent production experiments.

Repository documents were used as evidence and orientation, not assumed authoritative descriptions of current executable behaviour. For example, current CLI code proceeds through capture, derivation, and judging even though older workflow descriptions say it stops after derivation.

No production database was imported or inspected. No domain controller was contacted. No new production capture, deployment, or application code change was performed. The only repository addition made to deliver this review is this report.

### 2.3 Evidence labels

| Label | Meaning |
|---|---|
| Recorded production | A production observation retained in repository documentation or retained historical evidence; not a new measurement by this review |
| Source-confirmed | The current code performs the described work or follows the described dependency |
| Scaling risk | Algorithmic or retention behaviour that can grow poorly; not proof that production reached the worst case |
| Proposal | A design to evaluate; not implemented, accepted, or proven faster |

High confidence in a code path does not imply high confidence in its share of elapsed production time. That distinction applies throughout the findings.

### 2.4 Historical records must remain separate

The latest documented production analysis workload, the later production browse excerpt, older October 8 production records, lab measurements, and the uncommitted candidate are different evidence sets.

The Downloads pathname referenced by an older retained production handoff currently contains an October 9 lab log and summary. The review did not treat that replaced pathname as the original production log. Older production facts were taken from retained records instead.

The 4h38m production judging baseline had 20 recorded rules. The reviewed current application has 32 registered rules. Historical timing is evidence about workload and dominant phases, not a same-rule-count benchmark of the current tree.

Source paths in this report are relative to the Git repository root. Line ranges refer to the reviewed working tree and can move as other work proceeds.

## 3. Production-scale context

### 3.1 Latest documented completed production workload

The repository records the following October 10 workload from supplied production logs and summaries:

| Quantity | Recorded value |
|---|---:|
| Domains read / captured partitions | 9 / 11 |
| Objects captured and judged | 540,483 |
| Domain / Configuration / Schema objects | 510,468 / 24,944 / 5,071 |
| Derived principals | 405,982 |
| Saved nesting relationships | 2,593,737 |
| Distinct descriptors classified | 132,043 |
| Entry positions across those descriptors | 70,216,555 |
| Detailed assessment targets | 7,243 |
| Distinct requester questions / identities | 653,688 / 6,024 |
| Selection resources | 359 |
| Candidate selection considerations | 5,308,853 |
| Domain-object permission occurrences, separately counted | 257,173,028 |
| Evidence logical bytes | 10,332,127,232 |
| Derivation logical bytes | 3,057,782,784 |
| Judgement logical bytes | 25,171,054,592 |
| Total sealed logical bytes | 38,560,964,608 |

The 257.2 million domain-object permission occurrences and 70.2 million positions across distinct descriptors are different quantities. They must not be substituted for one another when estimating storage, work, or gains.

The position count is approximately 532 per distinct descriptor. Selection generated approximately 8.12 considerations per distinct question. These ratios describe cardinality, not isolated CPU or database costs.

Logical database lengths are not allocated disk space or peak working storage. WAL, temporary tables, capture shards, indexes under construction, and retained generations require additional capacity.

Sources: `docs\WHAT-THE-PRODUCT-IS.md:6606-6629`; `docs\PUNCH-LIST.md:390-398`.

### 3.2 Recorded elapsed time

| Observation | Recorded value | Interpretation |
|---|---:|---|
| First Dashboard navigation | 177.3 s | Later production browse excerpt, not current candidate |
| First Findings navigation | 96.1 s | Same browse excerpt |
| Combined first Dashboard and Findings | 273.4 s | Sum of the two recorded navigations |
| Opening/checking portion | 246.2 s, approximately 90% | Aggregated opening/checking work, not an isolated CPU-hashing measurement |
| Dashboard inventory query | Approximately 8.3 s | Separate remaining query cost |
| First tree construction | Approximately 13.5 s | Separate remaining navigation cost |
| Some warm Findings pages | Approximately 5.2 s | Hash isolation alone does not explain every warm delay |
| October 10 capture | 2h32m | Different stage and historical executable |
| October 10 derivation | 4m10s | Different stage and historical executable |
| October 10 judging | 4h38m | CompletedDegraded; not complete assessment of all possible questions |
| Combined path phases | 174.56 min | Approximately 63% of rounded judging duration |
| Selection | 1,370,147 ms, approximately 22.84 min | Candidate/key/witness processing |
| Evaluate/qualify/save batch | 5,345,931 ms, approximately 89.10 min | Combined timer cannot attribute all cost to one operation |

The 246.2-second bucket includes opening/checking work. Whole-file hashing is a source-confirmed mechanism, but the entire bucket must not be described as pure hash CPU time or pure disk reading.

Eliminating that bucket alone would leave approximately 27.2 seconds within the two recorded navigation durations. This is not a forecast: remaining queries, materialization, and screen dependencies still need attention. The inventory and tree timings should not be added again without reconciling their placement in the navigation record.

Sources: `docs\WHAT-THE-PRODUCT-IS.md:146-188,924-958`; `docs\PUNCH-LIST.md:27-35,390-403`.

### 3.3 Separate older capture evidence

The October 8 retained production record reports a 4h24m capture. SYSVOL consumed 9,811.1 seconds across 3,457 policies, approximately 62% of that capture. Final preparation included approximately 266.5 seconds building indexes and 126.5 seconds of backfill.

Those figures support investigating SYSVOL and preparation. They are not current-candidate timings and must not be mixed into the October 10 stage totals.

Sources: `.v-prod-completed-20261008-9c35\handoff.json:47-55`; `observed-log-facts.json:60-65,94-116`.

## 4. Current architecture: what is already worth retaining

The application is not an undifferentiated or entirely naive implementation. Existing improvements materially affect which recommendations are sensible.

| Area | Existing foundation |
|---|---|
| Capture | Descriptor-inclusive paged LDAP, ranged attribute retrieval, parallel per-domain shards, per-controller serialization |
| Evidence | Immutable captured bytes, explicit coverage and unknown states, raw descriptors, interned descriptor/ACE/trustee values |
| Derivation | Integer SID interning with scope separation, forward/reverse CSR adjacency, iterative strongly connected component discovery |
| Judgement | Descriptor-ordered processing, shared ACE/readings, prepared statements, 500-object batches, target-local preparation, prerequisite reuse |
| Proofs | Shared and fragmented components already exist; the proposal is to extend them, not invent sharing from zero |
| Publication | Generation identities, staged immutable files, atomic root selection, previous-generation preservation on failed publication |
| Readers | Selected-run protected file lifetimes, independent query connections, immutable SQLite reads, native progress-callback cancellation |
| UI | Asynchronous dispatch of reads, lazy selected object sections, bounded grids, generation-aware completion checks |

Examples: `next\src\SecureAD.Audit\Capture\CaptureRun.cs:330-367,770-775`; `next\src\SecureAD.Derivation\NestingGraph.cs:91-124`; `next\src\SecureAD.Judgement\JudgementWriter.cs:88-141`; `PreparedStatements.cs:40-69`; `next\src\SecureAD.Evidence\ProtectedStoreFile.cs:149-170,233-241`.

The current CLI does invoke derivation and judging after capture: `next\src\SecureAD.Cli\Program.cs:245-253`. The stale documentation-based claim that CLI never judges must not be used as a finding.

The current segmented candidate places its product tables before writing and moves payload ownership rather than simply copying a completed 25-GB database into another file. Its presence should be evaluated, not discarded or accidentally reimplemented.

## 5. Prioritized findings

Priority below is relative to the owner's immediate usability problem:

| Priority | Meaning |
|---|---|
| P0 | Directly addresses multi-minute saved-result opening or establishes a necessary serving boundary |
| P1 | Important interactive scaling or a major measured analysis workload |
| P2 | Longer-term capacity, capture throughput, recovery, or lifecycle improvement |

Priority is not a claim of an exploitable security issue or implementation approval.

### F01. Interactive integrity units remain too large

**Priority:** P0. **Evidence:** Recorded production plus source-confirmed mechanism. **Confidence:** High in the mechanism; current-candidate elapsed impact unmeasured.

`ProtectedStoreFile` protects selected database bytes against writes/replacement and verifies the selected file before a reader uses it. The verdict is retained for the protected lifetime, not persisted as an "already verified" flag across sessions.

That is an intentional integrity model. However, when the selected file contains gigabytes unrelated to the requested screen, first access is proportional to the entire file rather than the displayed result.

Current segmentation is a valid first response, but its benefit depends on product dependencies. A large PermissionProof or PathProof file remains an expensive first-access unit even after Findings becomes a separate database.

**Recommendation:** define independently sealed serving products aligned with screen needs and data locality. Give large detail/proof products bounded verification units. Keep a protected verified lifetime for each selected unit and exact source/generation binding.

Do not skip seals, trust timestamps, introduce a cross-session verification cache, or open unverified SQLite pages in the background while presenting authoritative results.

**Implementation difficulty/risk:** Medium for completing existing serving segmentation; high for a new page-verifying SQLite reader. A custom chunk/page-verification layer is an optional later design, not a prerequisite for the first correction.

References: `next\src\SecureAD.Evidence\ProtectedStoreFile.cs:43-83,107-136`; `BundleSealing.cs:88-90,148-175`; `StoreRootManifest.cs:6-29`.

### F02. Complete Findings loading still reopens heavyweight dependencies

**Priority:** P0. **Evidence:** Source-confirmed end-to-end call chain. **Confidence:** High.

The Findings screen requests filters and a page, then unconditionally requests its Tier-0 summary before applying the result.

```text
AssetsViewModel.LoadVisibleAsync
  -> ReadFindings
     -> ReadPage
        -> ReadFinding
           -> PermissionProof for several finding kinds
  -> ReadTier0FindingSummary
     -> OpenedRunResults.ReadJudgement
        -> OpenJudgement
           -> OpenEvidence
           -> OpenDerivation when declared
        -> JudgementReader.ReadTier0FindingSummary
           -> PathProof
```

`OpenJudgement` explicitly opens Evidence and, for a declared derived generation, Derivation. Thus a direct Findings reader measurement that avoids those files does not establish complete-screen independence.

Several typed finding branches also attach PermissionProof while materializing the page, including replication, delegation configuration, membership review, and attribute-write findings.

**Recommendation:** put small Findings/Tier-0 summary values in the lightweight serving product and route them through a lightweight reader. Separate a validated saved finding-list row from full typed proof retrieval. Load the selected proof only when the user opens detail.

This is not merely deleting the summary call or displaying a conclusion whose required saved data is missing. Publish an explicit summary/list product with its own validated contents, provenance, coverage, and refusal semantics.

**Expected effect:** removes known bulk dependencies from an ordinary list interaction. No production time reduction is established yet.

**Implementation difficulty/risk:** Medium, with important integrity and presentation-contract decisions. The existing candidate provides a foundation; this finding does not prove a wholesale rewrite is necessary.

References: `next\src\SecureAD.Shell\ViewModels\AssetsViewModel.Loading.cs:96-113`; `Services\BundleAssetSource.Paths.cs:165-166`; `Services\OpenedRunResults.cs:277-346`; `next\src\SecureAD.Judgement\JudgementReader.cs:271-277,623-720,1125-1179`.

### F03. Dashboard aggregates an object-scale navigation product on each showing

**Priority:** P0. **Evidence:** Source-confirmed; historical inventory timing. **Confidence:** High.

The candidate correctly routes Dashboard through Navigation instead of full Evidence. However, Navigation contains all captured object identities, and `InventoryReader` still groups the object rows by domain/class. Another query joins object rows to partition coverage to determine withholding state.

`DashboardViewModel.Show` resets its state and starts these reads again when the Dashboard is shown. The retained protected Navigation handle avoids rehashing during the same selected lifetime, but it does not make the aggregation constant-sized.

**Recommendation:** persist per-domain summary rows, coverage, class counts, GPO coverage, and the required membership counter during capture/analysis publication. The Dashboard should read a small overview product, not scan the object index.

The overview must describe recorded capture scope and incomplete domains accurately. Missing/unavailable is not zero. A materialized summary is a versioned saved product, not an informal cache that can silently become stale.

**Implementation difficulty/risk:** Medium; relatively contained if kept separate from security-rule changes.

References: `next\src\SecureAD.Evidence\Inventory\InventoryReader.cs:53-99,141-189`; `NavigationStorage.cs:35-71`; `next\src\SecureAD.Shell\ViewModels\DashboardViewModel.cs:488-521`.

### F04. Object pages perform scope-wide counting, computed sorting, and OFFSET work

**Priority:** P1. **Evidence:** Source-confirmed plus limited query-plan reproduction. **Confidence:** High in the work shape; actual production plans unmeasured.

Each object page requests a total, selects rows, and checks coverage. Ordering uses `SUBSTR/INSTR` over the distinguished name. There is no matching navigation sort-key index. Pagination discards earlier rows through OFFSET.

The subtree predicate uses a reversed-DN equality/prefix shape, but a matching column name does not by itself prove a seek. LIKE collation, OR predicates, bound parameters, and planner statistics matter.

**Recommendation:** persist an ordering key equivalent to the approved current ordering, add indexes matched to actual scope/filter/order combinations, and use generation-bound keyset continuation with a deterministic tie-breaker. Precompute stable scope counts where justified or avoid requiring an exact total for every page.

Do not silently change ordering, escaped-DN handling, inclusion of the selected container, case rules, or coverage semantics while changing access patterns.

A schema-only in-memory reproduction using the existing Release SQLite 3.53.3 library showed temporary B-tree sorting and a subtree scan. It used no production data or representative statistics and is not a production query-plan or timing result. Obtain exact current plans before attributing an additional collation defect or prescribing a particular index.

**Implementation difficulty/risk:** Medium; query shape and page contracts change, not security calculations.

References: `next\src\SecureAD.Evidence\ObjectListing.cs:137-159,166-177,196-230`; `NavigationStorage.cs:54-59`.

### F05. Search and ordinary object detail retain whole-Evidence first-access cost

**Priority:** P1. **Evidence:** Source-confirmed. **Confidence:** High.

Object search uses `instr(lower(distinguished_name), lower(search))` and a similar account-name predicate against Evidence. Rare or absent matches can require substantial scanning. Routing through `ReadEvidence` also exposes the first search to the large Evidence verification boundary.

Opening an object first reads its complete captured attribute model, including multivalued attributes. A group with a very large member list is therefore materialized before the membership section's 50-row identity-lookup paging takes effect.

**Recommendation:** serve search and initial object identity from an indexed compact projection. Retrieve requested attribute families and multivalued pages separately, using bounded detail segments where first-access integrity cost would otherwise remain excessive.

Preserve existing substring semantics if adding an FTS5 trigram or other search projection. Token search is not a drop-in equivalent. Keep exact recorded values and ordering available in detail.

**Implementation difficulty/risk:** Medium to high, depending on whether old-run projection and bounded detail segments are included in the first delivery.

References: `next\src\SecureAD.Evidence\CapturedObjectSearch.cs:15-23`; `ObjectAttributes.cs:204-249`; `next\src\SecureAD.Shell\Services\AssetReadRequest.cs:21-22,92-97`; `ViewModels\AssetsViewModel.Object.cs:65-86`; `GroupMembershipSectionViewModel.cs:40,69-75`.

### F06. Some Findings child collections defeat page-sized retrieval

**Priority:** P1. **Evidence:** Source-confirmed. **Confidence:** High in the mechanism; production share unknown.

SID-history values, service names, membership routes, and takeover-path collections have reader-local caches populated from whole child tables. A new JudgementReader is opened and disposed for each request, so "read once" can mean once per page request, not once per selected run.

**Recommendation:** retrieve child values in one bounded batch for the selected page's finding IDs. Avoid both one query per finding and loading every finding's children. Keep large proof bodies out of list-row materialization where the approved read contract permits it.

**Implementation difficulty/risk:** Medium. Preserve child ordinal/order and typed-evidence completeness.

References: `next\src\SecureAD.Shell\Services\OpenedRunResults.cs:151-189`; `next\src\SecureAD.Judgement\JudgementReader.cs:1424-1448,1553-1599`.

### F07. WPF still eagerly materializes the container hierarchy

**Priority:** P1 after bulk I/O isolation. **Evidence:** Source-confirmed scaling risk. **Confidence:** High; not attributed to the historical multi-minute opening bucket.

The tree reader constructs a whole container tree. Presentation recursively creates a TreeNodeViewModel for every node and subscribes to every node on the UI thread. Returning to Assets can reconstruct presentation from the retained tree. The reviewed TreeView and custom theme do not explicitly enable virtualization/recycling.

**Recommendation:** persist independently readable child/container relationships and global coverage summary. Materialize view models for visible/expanded branches, preserve expansion/selection by identity, and enable UI virtualization/recycling where compatible with the template.

Global coverage does not require clicking every branch if completeness/gaps are saved separately. UI virtualization alone does not avoid building the entire underlying data model.

**Implementation difficulty/risk:** Medium. Profile dispatcher construction/layout separately from database work before investing in template-level tuning.

References: `next\src\SecureAD.Evidence\DirectoryTree.cs:203-228`; `next\src\SecureAD.Shell\ViewModels\AssetsViewModel.cs:452-479,586-622`; `AssetRowViewModels.cs:47-53`; `Views\AssetsView.xaml:130-140`; `Themes\Tree.xaml:92-139`.

### F08. Pending analysis blocks reading previous completed results

**Priority:** P1 lifecycle improvement. **Evidence:** Source-confirmed. **Confidence:** High.

Publication retains previous completed generation files, but pending-attempt checks make saved-result lifetimes unavailable while Derivation or Judgement has unpublished changes. A long rebuild can therefore block useful previous results even when those immutable files are intact.

**Recommendation:** distinguish "latest attempt" from "selected completed generation." Permit an explicitly pinned previous complete generation while a new local worker builds its replacement. Label its age/generation; never present it as the new result.

This intentionally changes availability policy. It requires owner approval and adjusted validity rules, not removal of generation checks. Disk space must cover retained generations plus staging and temporary work.

**Implementation difficulty/risk:** Medium to high because lifetime, failure, deletion, and UI state interact. Not required to establish the first Dashboard speed improvement.

References: `next\src\SecureAD.Shell\Services\OpenedRunResults.cs:32-46,277-279,349-352`; `BundleAssetSource.cs:213-226`.

### F09. Path selection and evaluation have a large question/witness fan-out

**Priority:** P1, first analysis-throughput target. **Evidence:** Recorded production and source-confirmed structure. **Confidence:** High; exact internal cost allocation remains unknown.

Selection combines holders/members with resources, operation kinds, and terminal witnesses. Repeated candidate considerations reach persistence logic that validates and serializes data, checks conflicts/witnesses, and records uses.

The latest documented workload has 5.31 million considerations for 653,688 distinct questions. Resource preparation is reused, but requester assessments still examine relevant ordered ACEs and trustee/membership conditions. Worst-case assessment work includes the sum of question-count times ACL-length for each resource.

**Recommendation:** separate question identity from ordered witness-use occurrences. Generate/prepare each unique semantic question once per valid dependency context, while retaining all supporting uses separately. Batch resource-local assessment over compiled immutable ACL/context projections.

Do not assume identical ACE text implies identical permission meaning. Sharing keys must cover requester membership, resource/owner state, scope, schema/catalogue/recipe versions, SELF and deny behaviour, and uncertainty.

The 89.10-minute evaluate/qualify/save timer combines stages. Split that measurement before choosing between evaluation, serialization, lookup, and writing changes.

**Implementation difficulty/risk:** High. This is sensitive analysis work and should follow the browsing correction, not be bundled into it.

References: `next\src\SecureAD.Judgement\PathRequesterSelector.cs:74-108,187-254`; `PathRequesterSelectionStorage.cs:59-98`; `RequesterDaclAssessment.cs:123-195`; `docs\PUNCH-LIST.md:390-393`.

### F10. Classification sharing does not eliminate 70.2 million occurrence operations

**Priority:** P1. **Evidence:** Recorded cardinality and source-confirmed processing. **Confidence:** High; current table-space and CPU attribution unmeasured.

Classification correctly reuses descriptor-local preparation across descriptor-ordered objects. However, each position of each distinct descriptor still passes through interpretation and occurrence persistence. Shared entry/readings and WITHOUT ROWID storage reduce duplication but do not eliminate per-position work.

**Recommendation:** evaluate a SQLite-backed compact descriptor incidence product, with integer references to reusable interpretations and original raw ordinal/occurrence data. BLOB-packed vectors are one option, not an automatic choice: inverse lookups and page access may still require relational indexes.

Interpretations may be shared only across equivalent semantic dependencies. Save the interpretation rather than recomputing it during browsing.

The source contract is important: `DescriptorObjectStream` prepares one descriptor at a time, and `ObjectPermissionsReader` reparses its raw bytes. Judgement positions preserve raw ACL order and duplicates. Capture's sorted/deduplicated `descriptor_entry` list is not an equivalent substitute.

**Implementation difficulty/risk:** High. Start by measuring bytes/statements/allocations per descriptor and position, not by changing the encoding.

References: `next\src\SecureAD.Judgement\PermissionClassificationPreparation.cs:18-46`; `PermissionClassification.cs:48-64`; `PermissionClassificationStorage.cs:59-90,160-209`; `next\src\SecureAD.Evidence\DescriptorObjectStream.cs:96-104`; `ObjectPermissions.cs:412,577-584`.

### F11. Some prepared permission assessments are semantically replayed repeatedly

**Priority:** P1 analysis candidate. **Evidence:** Source-confirmed repeated work; phase timings are broader. **Confidence:** High in the call chain.

Full-control derivation invokes its evaluator twice per holder. Prepared-evidence validation invokes it twice again. Each invocation checks thirteen rights and scoped denies against the ordered ACL, plus proof-membership comparisons.

The recorded admitted-control and ownership phases took 12.69 and 21.73 minutes respectively. The review does not attribute those complete durations to this particular mechanism.

**Recommendation:** carry an immutable prepared result with exact source references through trusted internal stages, and independently validate/replay each unique result at a clearly defined boundary. Avoid repeated identical semantic work between stages that already share the same protected inputs.

This must not promote named-holder permissions into concrete-requester authorization or remove independent correctness checks without an equivalent boundary.

**Implementation difficulty/risk:** High for semantic changes; potentially smaller if confined to verified reuse within one existing context.

References: `next\src\SecureAD.Judgement\FullControlDeriver.cs:24-57`; `FullControlEvaluator.cs:14-29,77-89,99-148`; `ControlEvidencePreparation.cs:163-195`.

### F12. Shared proofs still incur repeated serialization and row-oriented work

**Priority:** P1. **Evidence:** Source-confirmed. **Confidence:** High; whole-run gain unproven.

The application already shares proof components. Remaining paths serialize for fingerprints, retrieve lookup candidates, compare serialized values, and serialize again on a write miss. Qualification data can be staged as JSON/hash, reread/decoded, and bound into a final product.

Some control/ownership products use per-target transactions and per-edge commands while other products use prepared batches. Conversely, the path pipeline has one long transaction spanning selection and substantial downstream work. Small proof fragments do not bound total transaction duration or WAL footprint.

**Recommendation:** extend typed immutable component identities and calculate canonical hashes once where safe. Use parent/reference structure rather than repeated expanded proofs. Retain ordered occurrence uses and collision checks. Introduce coherent bounded write batches with transactional cache promotion, preserving prerequisite and failure semantics.

Do not add multiple competing SQLite writers by default. Independent CPU work can feed one ordered writer, or independent product writers can own separate databases under a bounded publication plan.

Earlier storage trials reduced bytes without repeatable accepted speed benefit and could increase allocations. Compression is an experiment to measure end to end, not a guaranteed performance fix.

**Implementation difficulty/risk:** High. Retain existing shared-proof, prepared-command, and batching gains.

References: `next\src\SecureAD.Judgement\PathSharedProofStorage.cs:211-272`; `PathRequesterRiskStorage.cs:90-119,142-184`; `ControlEdgeStorage.cs:87-177,404-410`; `Tier0PathStorage.cs:73-239`; `next\artifacts\p251-storage-comparison\comparison-result.json:71-75,120-124`.

### F13. Graph, source, expansion, and path representations multiply retained memory

**Priority:** P1 capacity concern. **Evidence:** Source-confirmed retention; separate older memory snapshots. **Confidence:** High in the risk, not current peak memory.

Capture/derivation/judgement hold overlapping identity maps, attributes, pending/resolved edges, graph arrays, discovery candidates, requester expansions, and route caches. String-rich objects are repeatedly reconstructed across stage boundaries.

Judgement caches expansion per holder/mode, not per requester question. That avoids some recomputation but can retain large distinct expansions and requester-route populations. Qualified expansions used there are not bounded by the unrelated unqualified 5,000-member limit.

The older October 8 record contains approximately 10 million discovery candidates, 8.7 million resolved relationships, and private-memory snapshots around 11.9-12.9 GB. These are not current-candidate peak-memory measurements.

**Recommendation:** use one reusable SQLite-backed graph/fact representation with compact generation-local IDs, typed edges, column-oriented arrays or memory-mapped data where justified, and explicit lifetimes for expansions/results. Use sparse vectors, bounded caches, spill/sort, and byte budgets.

Keep durable GUID/scoped identity separate from local IDs. Captured membership, authorization membership, primary-group relationships, and protection propagation cannot share one undifferentiated adjacency policy.

**Implementation difficulty/risk:** High if replaced globally; manageable as one product at a time.

References: `next\src\SecureAD.Derivation\MembershipNestingPass.cs:163-217,308-401`; `next\src\SecureAD.Judgement\Tier0DiscoveryScheduler.cs:51-55,192-201`; `OwnershipScopeSelector.cs:26-98,136-146`; `RequesterMembershipContext.cs:36-57,223-259`; `.v-prod-completed-20261008-9c35\handoff.json:47-170`.

### F14. Global closure and latent derivation are not durable reusable answers

**Priority:** P1 structural issue; not established as the latest dominant duration. **Evidence:** Source-confirmed and algorithmic scaling risk. **Confidence:** High.

Stage2a constructs an all-group authorization closure, then runs latent-privilege derivation without saving the returned paths. The closure itself is not persisted as a general reusable result.

Closure building unions descendant sets per group. Its memory follows the sum of all materialized closures, and union work includes repeated overlaps. Budgets are examined after a component settles; cancellation is not checked inside every inner union/fixed-point operation. A pathological large SCC can therefore greatly exceed an intended logical-entry budget before the check.

A 10,000-group cycle implies approximately 100 million group-closure entries before a post-component limit check. This is an analytical stress case, not a production observation.

**Recommendation:** separate cycle inventory from optional closure materialization. Compute the required root/reachability products without indiscriminate all-pairs expansion where possible. Persist useful latent/closure outputs with coverage, or make an explicit product decision about not scheduling unused work. Do not delete analysis silently as a performance shortcut.

Use adaptive sparse sets, compressed bitmaps, SCC factoring, and shared witnesses selectively. A genuinely dense all-pairs answer still has an unavoidable output cost.

**Implementation difficulty/risk:** High because edge-policy and degraded-result semantics matter.

References: `next\src\SecureAD.Derivation\Stage2aRun.cs:301-310,555-564`; `AuthorizationMembershipExpander.cs:118-228`; `LatentPrivilegeDeriver.cs:82-109`; `ExpansionBudget.cs:34-39`.

### F15. Persisted graph readback repeats traversal and expands provenance

**Priority:** P1/P2. **Evidence:** Source-confirmed; call frequency and byte attribution unmeasured. **Confidence:** High in the mechanisms.

General `MembersOf` caches graph input but performs BFS for each requested root. Readback uses dictionary/list adjacency rather than reusing Stage2a's CSR representation. Several persisted route products repeat SID/scope/DN text in every path step.

Membership sources are retained as projected attribute objects, then serialized/hashed into source products and reconstructed for later use. Some summary entry points hydrate complete protection/route products to report counts; the post-publication portable-summary path can trigger full result loading twice.

**Recommendation:** provide explicit offline batch expansion products for the supported questions, with pageable saved answers and parent/witness references. Unknown future analysis requests should be separate offline jobs or explicit NotComputed states, not hidden work during browsing. Store dedicated summary/count products.

A substitution must validate semantics: the generic membership reader's primary-group handling differs from other derivation products. This is a compatibility guard for redesign, not a proposal to silently change rule output.

**Implementation difficulty/risk:** Medium for dedicated summaries; high for general expansion/provenance replacement.

References: `next\src\SecureAD.Derivation\DerivationReader.cs:381-392,506-518,630-805,980-999`; `MembershipRouteStorage.cs:28-39,75-87,93-166`; `MembershipInputStorage.cs:27-82`; `Stage2aRun.cs:110-129`.

Merely reading `bundle.StreamObjects().IsComplete` does not enumerate the objects. `BundleReader.StreamObjects` returns metadata plus a lazy sequence. The review does not allege an extra full evidence pass from that call.

Reference: `next\src\SecureAD.Evidence\BundleReader.cs:510-512`.

### F16. Capture acquisition is coupled to CPU/storage work and repeated rewriting

**Priority:** P2. **Evidence:** Source-confirmed. **Confidence:** High; isolated throughput impact unmeasured.

The page loop finishes entry processing and synchronous writing before fetching the next page. Each object's descriptor is parsed/normalized before the writer checks descriptor reuse. Thus storage deduplication does not deduplicate parsing/normalization CPU.

Domains are captured concurrently to private shards, but consolidation waits for completion and merges them serially into a final database. This is set-based SQL, not an application row-by-row merge; nevertheless, much data is written to staging and then rewritten into the final store.

Prepared commands and long transactions already avoid a transaction/fsync per ACE. The remaining operation count still scales with objects, multivalued attributes, descriptor occurrences, and distinct values.

**Recommendation:** use bounded byte-budgeted acquisition/processing/ingestion stages; identify duplicate raw descriptor content before expensive processing. Consider retaining immutable SQLite domain shards under a complete-generation manifest instead of consolidating all raw evidence.

If a final combined database remains necessary, overlap private consolidation with completion where safe, and measure contention. Preserve exact source observations, raw ACLs, authorized scope, and complete-generation publication.

**Implementation difficulty/risk:** High. It is not needed to fix a saved Dashboard.

References: `next\src\SecureAD.Audit\Capture\PartitionCapture.cs:236-275,313`; `BundleCaptureSink.cs:290-293`; `CaptureRun.cs:348-414`; `next\src\SecureAD.Evidence\BundleWriter.cs:780-863,1652-1664`; `BundleMerge.cs:164-205,301-323,353-387`.

### F17. SYSVOL is serial and performs repeated traversal

**Priority:** P2, strongest capture-specific historical timing lead. **Evidence:** Source-confirmed and separate recorded production. **Confidence:** High.

SYSVOL begins after LDAP consolidation. Policies are awaited individually through one isolated reader with serialized operations. Policy processing recursively enumerates directories and files in separate passes, with another optional XML traversal.

The older production record's approximately 2h43m SYSVOL duration makes this a worthwhile structural investigation. Repeated traversal is confirmed, but its exact share of that duration is not isolated.

**Recommendation:** one comprehensive policy inventory walk, then bounded workers across domain/share endpoints and staged SQLite output. Preserve folder, script, and content-file ACLs, source paths, unreadable/partial states, and policy coverage. Keep the isolated worker and inactivity protections.

Concurrency must respect controller/share load. Skipping SYSVOL, scripts, or failed policies is a coverage change, not a free optimisation.

**Implementation difficulty/risk:** Medium to high. Benefits depend on endpoint latency and serialization bottlenecks.

References: `next\src\SecureAD.Audit\Capture\CaptureRun.cs:399-441,482-503`; `Sysvol\SysvolCapture.cs:136-145,232-249,317-323,385-403`; `IsolatedSysvolFileReader.cs:73,130-177,239-245`; `SmbSysvolFileReader.cs:119-128,199-233`.

### F18. Recovery and retained capture caches are too coarse

**Priority:** P2. **Evidence:** Source-confirmed operational cost/retention risk. **Confidence:** High.

Conversation loss restarts a partition, failover can discard the shard, and a new writer removes prior partial paths. A late failure can repeat much of a large domain's work. Reusing a paging cookie after the LDAP conversation dies is not a valid fix.

Completed domain results retain sinks/writers and their dictionaries while other domains, consolidation, and SYSVOL continue. Disposing database resources does not release dictionaries while the containing object remains reachable.

**Recommendation:** return compact persisted segment identities, policy metadata, coverage, and timings from completed units. Introduce durable completed-unit checkpoints under an explicit observation-window policy. Bound interning/caches by bytes with durable backing or sorting where necessary.

A resumable smaller-than-partition capture needs a proven complete, nonoverlapping acquisition strategy. Arbitrary DN subdivision is not enough.

**Implementation difficulty/risk:** High for durable resume; medium for reducing completed-writer retention.

References: `next\src\SecureAD.Audit\Capture\PartitionCapture.cs:118-126`; `RetryPolicy.cs:102-112,136-158`; `CaptureRun.cs:656-660,695-724,793`; `next\src\SecureAD.Evidence\BundleWriter.cs:88-122,212-217,398-435,1851-1859`.

### F19. Evidence/projection version coupling can make improvement require recapture

**Priority:** P1 migration concern, P2 general architecture. **Evidence:** Source-confirmed policy. **Confidence:** High.

The Evidence reader refuses exact storage/catalogue/parser/canonicalization mismatches and tells the operator to recapture. That can turn an offline projection or parser improvement into another production acquisition even when the original raw observations exist.

**Recommendation:** separate the versioned immutable raw-evidence contract from parsing, analysis, and serving recipes. Support nominated historical evidence versions through read-only decoding and publish new disposable products beside them, bound to the original seal.

This does not mean silently interpreting an incompatible schema, rewriting old evidence, or inventing observations. Missing required attributes still require explicit unavailable results or separately approved recapture.

The first usability release needs an explicit decision on existing production-run compatibility before implementation. Do not surprise the owner with a recapture requirement at the end.

**Implementation difficulty/risk:** Medium to high for a narrow nominated-version path; substantially higher for universal historical compatibility, which is not recommended.

References: `next\src\SecureAD.Evidence\BundleReader.cs:293-362`; `docs\next\WORKFLOW.md:95-113`.

### F20. The performance acceptance objective is misaligned with usability

**Priority:** P0 process decision. **Evidence:** Documented current candidate gate. **Confidence:** High.

The candidate was rejected when checkpoint median rose from 11 to 30.5 ms, database closure from 7 to 16 ms, and generation-file moves from 2 to 6 ms on the small synthetic. These are real reported observations under the existing owner-approved rule.

They are not an explanation for hours of judging or minutes of saved-result opening. A gate that vetoes any subphase change outside a small baseline repeat range can make a materially better architecture impossible to adopt without establishing user-visible benefit.

**Recommendation:** obtain explicit owner approval for material, end-to-end budgets with separate first-view, warm-view, total analysis, peak-memory, disk, and publication measures. Keep semantic, integrity, and failure gates strict. Keep subphase diagnostics, but interpret fixed overhead in the context of whole-stage and user-facing outcomes.

Do not silently waive the existing rule or claim the candidate accepted. Compare complete workflows on equivalent inputs, with repeat variability and resource contention recorded.

**Implementation difficulty/risk:** Primarily a decision and measurement-design task, not an excuse to avoid performance accountability.

Reference: `docs\WHAT-THE-PRODUCT-IS.md:260-291`.

## 6. Recommended target architecture within WPF and SQLite

### 6.1 Overall shape

```text
Bounded capture pipeline
        |
        v
Immutable raw SQLite evidence segments + capture manifest
        |
        v
Versioned parsing / identity / graph / fact products
        |
        v
Batched offline assessment + shared proof components
        |
        v
Atomically published serving products
        |
        v
WPF: summaries, indexed pages, requested detail only
```

SQLite remains the durable database technology. Compact arrays, packed vectors, or typed BLOBs are representations inside or alongside that processing model, not a proposal to replace SQLite with another database engine. Start with relational forms where they meet the workload.

The principal architectural replacement is "one representation serving every stage" with distinct acquisition, analysis, and consumption products. WPF remains the presentation technology.

### 6.2 Proposed product boundaries

Names below are conceptual, not approved filenames or a shipping schema.

| Product | Contents | Required interactive dependency |
|---|---|---|
| Capture manifest | Source identity, observation intervals, scope, segment declarations | Small metadata only |
| Overview | Coverage, per-domain counts, stage outcomes, small saved counters | Dashboard should need only this and compatible small roots |
| Browse/search | Object identities, class, domain, parent, persisted sort/search keys | Tree/list/search pages |
| Findings list | Saved list rows, rule outcomes, filter values, small Tier-0 summaries | Findings list without expanded proofs |
| Object detail | Captured attributes and ordered multivalued observations | Requested object/family/page |
| Permission/detail proof | Ordered raw occurrence references, saved interpretations, selected proof components | Selected detail, not ordinary Dashboard |
| Graph/facts | Typed adjacency, identities, source-value references, reusable saved analysis | Offline processing; compact saved projections for browsing |
| Path detail | Shared proof components, requester answers, route witnesses | Selected path/detail pages |

A product can occupy one or more SQLite files. Do not create a file per object or automatically a file per table. Choose boundaries by byte size, access locality, and expected sharing. A role containing nearly all proof data can still be too large.

### 6.3 Integrity and trust contract

Selected products must retain exact capture/resource/generation/recipe binding. Publication should validate the products it creates, seal the final bytes once, and atomically select a complete generation. Readers verify the actual selected unit before use and retain protection while using it.

A summary is a saved conclusion derived during analysis, not fresh analysis. If only the overview has been checked in this session, the UI must not claim all raw evidence and detail proofs have been verified.

A missing or damaged required selected product must refuse explicitly. Whether an unrelated damaged detail segment makes a verified summary unavailable is a deliberate product decision. Root-manifest completeness and per-view readiness should be designed together rather than changed accidentally.

Whole-file integrity verification of every byte in a 38.6-GB corpus cannot become constant-time through a query optimisation. The choices are smaller independently verifiable products or a properly engineered verified chunk/page access layer.

Merkle/chunk verification would require all consumed data and database metadata to be verified before use through a controlled reader/VFS. Merely storing page hashes while ordinary SQLite can read unchecked pages is insufficient. This is a higher-risk optional design, not the initial implementation recommendation.

### 6.4 Graph, question, and proof contracts

Use compact local IDs for efficient execution and stable GUID/scoped identities for durable meaning. Maintain edge policy/type, original observation references, observation coverage, and explicit unknowns.

Separate unique questions from ordered witness uses. Separate immutable proof components from uses that identify resource, descriptor, ordinal, target, and generation. Do not collapse duplicate evidence occurrences or independent routes merely because component payloads match.

Preserve raw ACL order and duplicate occurrences. Preserve captured-membership and authorization distinctions, primary-group rules, distribution/security-group rules, and domain-local scope. Share only when all semantic dependencies match.

### 6.5 Local worker and generation lifecycle

A local background worker process can own expensive capture/analysis/index work while WPF remains responsive. No service, remote agent, or central database is required.

The UI should be able to pin a labelled completed generation while another attempt runs, subject to an approved availability policy. Old/new final products, staging, WAL, temporary indexes, and capture shards require explicit disk budgeting.

For scale context only, two copies of the recorded final 38.56-GB footprint would already be about 77.1 GB before temporary work. This is not a capacity forecast for the redesigned application.

### 6.6 Incremental operation

First implement reuse within one immutable generation. Cross-run content reuse can follow once dependencies are explicit.

DirSync is not a drop-in replacement for a complete permissions snapshot. Microsoft's documentation notes that inherited permission changes and ancestor moves need not return every affected descendant. A correct incremental design must handle those dependencies, deletions, replica/cookie provenance, attribute deltas, SYSVOL changes, and full-resync fallback.

No incremental capture implementation is recommended for the first usability release.

## 7. Delivery plan and feasibility

### 7.1 What is realistically doable

The existing codebase has enough separation and useful infrastructure to support staged correction. The responsive-saved-results project is narrower than replacing graph algorithms, rules, and capture.

The first release can largely preserve capture observations and security calculations while changing which finished products the UI opens. That still requires careful reader, publication, integrity, and compatibility work; it is not a trivial UI patch.

Deeper judgement and graph changes are substantial engineering. They should not be represented to a non-developer owner as a quick, safe global refactor.

### 7.2 Proposed releases

| Release | Scope | Excluded from that release | Difficulty/risk |
|---|---|---|---|
| R0: agree contracts | Baseline, old-run compatibility, selected-product integrity, targets, rollback and comparison policy | Application implementation | Low code risk; necessary decisions |
| R1: responsive overview | Dedicated Dashboard summary and actual complete-screen isolation | Rules, graph algorithms, capture concurrency | Medium |
| R2: responsive Findings | Lightweight list/filter/summary, selected detail, bounded proof dependencies | Judging semantic redesign | Medium to high |
| R3: predictable browsing | Indexed/keyset pages, search projection, page-local children, measured WPF materialization | New capture scope or rule meaning | Medium |
| R4: targeted analysis | Question/witness plan, prepared ACL reuse, proof/incidence work, one product at a time | Whole-engine simultaneous replacement | High |
| R5: capture/recovery | SYSVOL, bounded pipeline, retained shards, retention/resume | Unproven incremental snapshot | Medium to high |

R1-R3 are the immediate usability programme. R4-R5 can be independently prioritised after actual browsing acceptance.

For broad planning, dependable browsing correction is a weeks-scale engineering task, not an hours-scale patch. The deeper pipeline work can require additional weeks or months. These are planning bands, not estimates or commitments. Scope, old-format support, developer availability, and required production acceptance determine the schedule.

### 7.3 Existing candidate disposition

Do not restart the segmented work merely because it is unfinished. Preserve it as a candidate and identify which pieces meet the new explicit serving contract.

First resolve the full-screen dependencies in F02 and the tiny-summary requirement in F03. Measure the complete screen before deciding whether more extensive physical sharding is needed.

The reviewed candidate was not accepted under its existing gate. This report neither accepts it nor authorizes weakening its gate without an owner decision.

### 7.4 Decisions required before implementation

| Decision | Why it matters |
|---|---|
| Which existing production evidence versions must remain usable? | Determines read-only adapters/projection construction and avoids surprise recapture |
| What can a verified list/summary claim before detail segments are verified? | Defines trust, refusal, and presentation boundaries |
| Are selected-segment failures isolated or whole-generation failures? | Determines availability and integrity semantics |
| What are the cold/warm latency and total-analysis budgets? | Prevents microbenchmarks from replacing the real objective |
| Can previous completed results remain visible during rebuilding? | Changes pending-attempt and generation-currentness policy |
| How much memory/disk headroom is available? | Bounds workers, generations, staging, and caches |
| Which release is approved, and what is explicitly excluded? | Prevents a bounded correction becoming an unreviewable rewrite |

Owner review of this report does not answer or approve those decisions automatically.

## 8. Acceptance and measurement plan

This section describes proposed future acceptance. It is not a claim that the report-writing task performed those experiments.

### 8.1 Proposed responsiveness targets

| Interaction | Initial proposed target |
|---|---:|
| Cold Dashboard to useful displayed content | Under 2 s |
| First ordinary list/Findings page to useful displayed content | Under 1 s |
| Warm paging | Under 250 ms |

These are discussion targets, not achieved results or approved requirements. Define agreed hardware, storage, dataset, page contents, percentile, and cold-cache meaning before using them as pass/fail criteria.

Distinguish a new process, a newly selected run, and a cold OS cache. Label whichever condition was actually measured.

### 8.2 Measure complete user actions

Measure click/command through useful rendered content, not only an internal reader call. Include summary requests, filters, proof hydration, open/check time, lock waiting, query execution, DTO/view-model construction, dispatcher work, and layout.

Record selected segment roles, bytes hashed, source/generation identity, connection count, rows/materialized bytes, and cancellation outcomes. A Findings benchmark must include its summary and the relevant finding types.

The direct-reader and actual-screen dependency sets should be compared explicitly. A hidden path to Evidence/Derivation/proof stores should fail the intended lightweight-screen contract.

### 8.3 Match production shape, not only object count

| Dimension | Required coverage |
|---|---|
| Objects/domains | Approximately 540k or larger, nine domains, realistic skew and long names |
| Descriptors | Approximately 132k distinct descriptors and 70m raw positions, low/high reuse |
| Membership | Approximately 2.59m saved relationships, hubs, shared diamonds, deep chains, large SCCs |
| Requesters | Approximately 6k identities and 653k questions with repeated witness considerations |
| Semantics | Denies, SELF, scoped rights, primary groups, ambiguous scoped SIDs, foreign references, missing attributes |
| Findings/detail | Representative finding types, child-value distributions, large proofs and routes |
| Failure | Cancellation, late write failure, missing/changed/substituted selected product, interrupted publication |

A 12,000-object/590,000-entry synthetic can establish useful behaviour and compare candidate implementations. It cannot establish capacity at 70 million descriptor positions or 653,688 questions. Filler objects without realistic relationships do not reproduce the expensive workload.

Use approved synthetic profiles or owner-run aggregate measurements. Do not request or export production databases as an automatic next step.

### 8.4 Analysis/capture measurements

For judgement, separate selection keys/witnesses, semantic evaluation, serialization/hash/comparison, SQL calls/binds, lookup plans, staging/final writes, validation, index creation, checkpoint, close, and sealing.

For derivation, separate evidence enumeration, source persistence, graph construction, closure/root propagation, route construction, indexes, summaries, and publication. Count duplicate/unique edges and closure/witness states.

For capture, separate LDAP/range wait, parse/normalize, sink writes, shard commit, merge, SYSVOL operations, backfill, indexes, and sealing.

For every stage record peak private/managed memory, allocations/GC, working-file high-water bytes, queue bytes, logical output, physical writes where available, and repeated-run variability.

### 8.5 Semantic and lifecycle preservation

Compare saved answers, coverage, finding identities, typed evidence, witness order/multiplicity, and source/resource/generation binding. Counts alone are insufficient.

Differences that necessarily name a new generation should be handled through an explicit comparison rule, not by ignoring broad fields. Missing evidence must not become clean/empty success.

Publication failure/cancellation must preserve the previous completed selection. Corruption and source-substitution controls must still refuse. Browsing must perform no new graph/permission judgement merely because a screen opens.

Keep original evidence untouched. New disposable projections must be beside it, not a rewrite of the only sealed copy.

### 8.6 Performance materiality

Use alternating equivalent-input repeats with exact executable/source provenance. Keep operation-level diagnostics but evaluate regressions against approved absolute and relative materiality, repeat variability, and complete user/stage outcomes.

A tens-of-milliseconds publication change must not automatically outweigh minutes of interactive improvement. Conversely, an attractive screen benchmark must not hide a material analysis slowdown, memory explosion, or disk requirement.

## 9. Risk controls and non-goals

### 9.1 Principal risks

| Risk | Required control |
|---|---|
| Quicker screen silently weakens evidence guarantees | Explicit selected-product trust contract and refusal states |
| New projection makes existing runs unreadable | Decide nominated-version compatibility before coding |
| Compact representation changes ACL order/duplicates | Preserve raw occurrence contract and compare typed evidence |
| Graph reuse confuses membership semantics | Typed policies/edges and explicit primary/scope handling |
| More workers exhaust memory or overload directory endpoints | Byte budgets, bounded concurrency, per-endpoint limits |
| New generations exhaust disk | Capacity model including old/new/staging/WAL/temp products |
| Refactor changes findings while being called performance-only | Exact result/coverage comparison and separately approved semantic corrections |
| Successful narrow benchmark misses real screen path | Complete rendered interaction and segment-dependency measurement |
| Competing assistants overwrite candidate work | One implementation owner; separate read-only reviewer; no simultaneous edits to the same change |

### 9.2 Not recommended

Do not replace WPF or SQLite. Do not make a server, service, or remote agent a prerequisite for local usability.

Do not reduce capture scope, disable rules, truncate memberships, suppress unknowns, or drop duplicate proof occurrences to satisfy timing targets. An explicitly approved scoped analysis mode is a different product decision.

Do not introduce cross-session verification flags, skip seals, rewrite frozen evidence, or assume file timestamps prove unchanged bytes.

Do not enable incremental capture by treating DirSync as a complete snapshot of inherited permissions or descendant names.

Do not start with a universal graph/proof rewrite, new compression format, or custom verified SQLite VFS before demonstrating what the bounded serving correction achieves.

## 10. Questions for the independent Copilot cross-review

The parallel reviewer should confirm, refute, or qualify the findings against the actual working tree. Agreement in wording is not evidence.

| Question | Requested evidence |
|---|---|
| Does complete Findings loading follow F02, including Tier-0 summary and proof dependencies? | Exact production call chain and all selected file roles |
| Does the current candidate already avoid any alleged dependency? | Code and a complete-view trace, not only a direct-reader benchmark |
| Are Dashboard numbers still aggregated from object-scale rows? | Actual SQL and repeated-show behaviour |
| Which old production format can the proposed correction read? | Supported read path and precise missing-input/recapture boundary |
| Which selected-result guarantees require full underlying proof verification before list display? | Existing contract plus explicit proposed change |
| Which of F09-F12 dominates current judging after existing optimisations? | Separated equivalent-input timings and operation counts |
| Are latent paths/closure outputs actually persisted or consumed somewhere omitted here? | Producer, storage, consumer, and host reachability |
| Do membership-reader semantics permit the proposed shared graph substitution? | Primary/security/distribution/scope/unknown cases |
| Does current source preserve the repeated full-control call chain? | Exact calls and any existing preparation/memoization that eliminates them |
| How should proof sharing preserve raw ACL occurrence order and duplicate uses? | Typed data contract and storage/readback design |
| Is a smaller staged correction sufficient before broader restructuring? | Minimum coherent serving boundary and evidence of expected materiality |
| What are the largest migration/failure risks this report missed? | Concrete mechanism, affected product, and a bounded control |

Useful review dispositions are Confirmed, Qualified, Refuted, Already addressed in current tree, or Needs measurement. For disagreements, record exact source/trace evidence and which consequence changes.

Do not treat the report as instructions to edit the application. The owner intends to compare both reviews, obtain cross-review, select a path, and then decide where implementation will occur.

## 11. Supporting first-party technical references

External references ground platform behaviour, not the app-specific findings:

| Topic | Reference |
|---|---|
| SQLite query-planner/index/LIKE constraints | <https://www.sqlite.org/optoverview.html> |
| SQLite as a desktop application format and limits of deployment choices | <https://www.sqlite.org/whentouse.html> |
| FTS5 search options; evaluate trigram behaviour rather than assume token equivalence | <https://www.sqlite.org/fts5.html> |
| Microsoft.Data.Sqlite async methods execute synchronously | <https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/async> |
| WPF UI virtualization versus data virtualization | <https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/optimizing-performance-controls> |
| DirSync limitations for inherited changes and descendants | <https://learn.microsoft.com/en-us/windows/win32/ad/polling-for-changes-using-the-dirsync-control> |

Changing method names to Async does not create asynchronous SQLite I/O. The current worker-dispatch approach is appropriate in principle; the important issue is how much work is dispatched and how much data the UI later materializes.

## 12. Owner-facing decision summary

The code is not beyond repair, and WPF/SQLite do not prevent the recommended improvements.

The first decision should be a bounded responsive-saved-results programme, not approval of every architectural idea in this report. Preserve the current candidate, make complete screen dependencies explicit, keep original evidence intact, and establish production-shaped acceptance.

The deeper graph, proof, and capture changes are credible opportunities, but they are larger and riskier than the initial browsing correction. Their scope and value should be decided from separated workload evidence, not from a promise that rewriting everything will be faster.

**Implementation remains unapproved. No application edit, capture, deployment, commit, or push is authorized by this report.**
