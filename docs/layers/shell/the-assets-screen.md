# The assets screen

**Code:** `next/src/SecureAD.Shell/ViewModels/AssetsViewModel.cs`, `AssetRowViewModels.cs`,
`ObjectViewModel.cs`, `ObjectSections.cs`, `ObjectSectionCatalog.cs`, `FactState.cs`,
`ControlEdgesSectionViewModel.cs`,
`next/src/SecureAD.Shell/Services/IAssetSource.cs`, `BundleAssetSource.cs`
**Layer:** Shell — what one run captured and what the judging concluded about it: the directory as
its evidence can rebuild it, the objects in the part of it the operator selected, the findings, and
one object read in full.

[`ShellSection`](../../../next/src/SecureAD.Shell/ViewModels/ShellSection.cs) describes `Assets` as
*what the selected run captured*. The objects, the findings and an opened object are all that one
member: an object is opened from the grid rather than navigated to, so there is one screen here and
not three. The run is chosen on [`the home screen`](the-home-screen.md); the audit that produced it
is planned on [`the New Audit screen`](the-new-audit-screen.md).

As with every shell page, the types below are `internal` — the window exports nothing, and
`ShellSurfaceGateTests` fails the build the day it does.

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `AssetsViewModel` | The assets of one run: the tree, the objects, the findings, and which object is open |
| `IAssetSource` | How a bundle's tree, objects, permissions and findings are read |
| `BundleAssetSource` | Those reads, over a real bundle and the judgement beside it |
| `TreeNodeViewModel` | One container in the tree, and whether it was captured |
| `TreeGapViewModel` | Something the tree does not show, and why |
| `ListedObjectViewModel` | One object in the listing, as a grid row |
| `FindingRowViewModel` | One finding in the grid, as the judging stored it |
| `LapsComputerViewModel` | One computer in the LAPS inventory: both expiration dates, what it is capable of running, and — where a rule leaves it alone — which exclusion did it |
| `LapsCountViewModel` | How many computers are in one LAPS state across the whole container, including the states nothing is in |
| `RuleRowViewModel` | One rule: what it looks for, and what it did to this run — including the several ways it can report nothing |
| `ObjectPaging` | Where one page of a listing starts and how large it is |
| `FactState` | The three states every fact on this screen is drawn in |
| `ObjectViewModel` | One object opened in full: its sections, and which is showing |
| `ObjectSectionDefinition` | One section a class of object has, and the attributes that justify it |
| `ObjectSectionCatalog` | Which sections each class of object has |
| `ObjectSectionViewModel` | What every section of an opened object has in common |
| `OverviewSectionViewModel` | What this object is, said first |
| `AccountSectionViewModel` | What the directory records about an account |
| `PermissionsSectionViewModel` | Who can do what to this object |
| `ControlEdgesSectionViewModel` | Paged stored control edges, read by target or named holder, with coverage and hidden expected counts |
| `ControlEdgeRowViewModel` | One stored capability's wording, classification and supporting evidence |
| `SelfMembershipAssessmentRowViewModel` | Plain-language stored requester answers and their identity, permission and route evidence, separate from holder-edge counts |
| `EvidenceSectionViewModel` | What was captured about this object and what was not |
| `FindingsSectionViewModel` | What the judging concluded about this one object |
| `PolicyLinksSectionViewModel` | The policy linked at this container |
| `AttributeSectionViewModel` | A group of attributes shown together |
| `OtherValuesSectionViewModel` | Captured values no section claimed |
| `NotBuiltSectionViewModel` | A section named but not yet built, which says so rather than looking empty |
| `AttributeValueViewModel` | One attribute value, and whether it was captured at all |
| `PermissionVocabulary` | The words this forest uses for its own rights and classes |
| `PermissionCounter` | One count on the permissions section, and what it means |
| `PermissionRisk` | How much an entry on the permissions section is worth reading |
| `PermissionRightViewModel` | One right within a permission entry |
| `PermissionEntryViewModel` | One entry on an object's access control list |
| `PrincipalGroupViewModel` | The entries belonging to one principal, shown together |

<!-- TYPES:END -->

This table is the page's claim of ownership, bound in both directions against the internal types the
files above declare, by `ShellLayerTypesTests`.

The views over these — `AssetsView.xaml`, `FindingsView.xaml`, `ObjectView.xaml`,
`ObjectSectionList.xaml`, `GapsCard.xaml` and `Sections/ObjectSectionTemplates.xaml` — declare no
types of their own. What holds them is `ViewBindingGateTests` and `ViewResourceGateTests`, the
second of which exists because a view naming a resource the application never defined crashed the
product in front of the owner on 2026-08-26 with the build green and 2,410 tests passing.

---

## Four silences, kept apart

An empty screen is not one fact, and this screen refuses to draw four different ones the same way.

- **No run chosen** is a question the operator has not answered.
- **A capture is running** is a refusal with a remedy: wait. The bundle is not read at all while one
  is writing it.
- **A bundle that would not open** is a failure he needs to see, in the words the evidence layer
  used rather than reworded here.
- **A container that was read and holds nothing** is an empty container, which is a claim worth
  making.

Showing an empty list for all four would say *there is nothing here* in three cases where that is
not known to be true. That is
[`0002`](../../decisions/0002-absent-view-means-degraded-run.md) exactly, and it is the rule the
whole screen is built around.

---

## Stored control edges on an object

`ControlEdgesSectionViewModel` reads the stored product through `IAssetSource`; the screen does not
calculate directory access. By default it shows rights over the opened object. When that object has
a principal SID, **Rights held by this principal** switches to the named-holder view of the same
stored edge set. This is not expansion of the rights the principal receives through group membership.

The current slices cover WRITE_DAC, WRITE_OWNER, bounded group-membership rights, password-reset
permission, key-credential write permission, bounded replication permissions and existing-owner control. General
membership writes and own-account-only Self-Membership candidates have different labels. The latter
remain unknown because no concrete requester operation is evaluated. The evidence view shows their
`MembershipEscalation` category, evaluation, constraints and research status without calling the
target group privileged. Unknown candidates remain counted, and the coverage text says that
expectedness is not proof of an established capability. Its scope notice explicitly names capabilities
not yet derived, so its counts cannot be read as totals for all control. Expected primitives are
hidden by default, with expected, unexpected and unknown-expectedness counts stated separately.
Showing expected edges changes the filter, not the stored classification. Supporting ownership
compounds remain separately labeled, unknown and uncounted; these are not findings or severity grades.

First/next-page controls read bounded pages. Changing views or filters returns to the first page;
if the judgement generation changes during paging, the view refuses to mix results and asks the
operator to return to the first page. A missing or unreadable product says so rather than presenting
a complete empty result. Holder-first coverage retains capture-wide unanswered-object counts,
because an unread descriptor could name the selected principal.

### Requester and control readback safety — R4

**Corrected and tested offline.** A judgement generation identifies one completed judging run.
Control edges and requester assessments are read separately, so a new judgement published between
those reads must not leave answers from two runs on the same object screen.

- Every load clears both sets of rows, selected edge, next-page availability and prior success
  wording before attempting a read. A failed control read therefore cannot leave a previous
  requester's answer visible, including after paging, changing direction/filter or reconfiguration.
  Since R7, the selected requester and its proof clear with those rows too.
- A completed control product needs a generation identity. Where requester readback applies, a
  completed requester product also needs one and must match the control page, including an empty
  completed requester product. A generation change during paging or between reads withholds both
  sets of rows and counts, leaves no selected edge or next page, and asks for the first page.
  Neither product's rows are published before that comparison finishes.
- A requester-read failure clears its old rows and states the failure, while the successfully read
  control page may still be displayed. A requester product that was not derived remains distinct
  from a completed product with no scheduled request; absence has no requester generation to match.
  A direction that does not apply to requester readback neither reads nor reuses requester rows.
- Configuring a selected object reads each applicable product once. The direction-change callback
  does not trigger a second initial read while configuration is in progress.
- Reloading/changing a run closes old object detail even when the tree has no selected node. Trying
  to open another object clears the old detail before a failed or missing-object result can return.
  Object read callbacks retain the bundle path that opened the object rather than reading the
  screen's later selection. Returning to the first page can then load a matching new generation.

`ControlEdgeReadbackSafetyTests` exercises these cases through the real view-model commands with
synthetic source results. Its assertions inspect both rows and refusal/coverage states, and record
the bundle/selection actually passed to both readers. They do not launch a window or contact AD.
`ControlRowsAreNotPublishedBeforeRequesterGenerationIsChecked` checks the state during the second
read, not merely after it; `DifferentGenerationsBetweenReadsWithholdBothProductsUntilFirstPage`
also proves recovery and covers both populated and empty requester results in both directions.

**Validation:** the same `ControlEdgeReadbackSafetyTests` and `ControlEdgePresentationTests`
selection ran **47 cases: 18 passed and 29 failed before the production correction, then 47/47
passed after it**, with no test edits between those runs. Existing presentation fixtures were
given coherent generation identities before the first run; no frozen historical values changed.
The additional `AssetsViewModelTests`, `SelfMembershipRequesterTests`, `JudgingEndToEndTests`,
`SelfMembershipStorageTests` and `ControlEdgeStorageTests` selection passed **348/348**. A fresh full
`SecureAD.Next.Tests` run passed **3,703/3,703**, none skipped, and the full solution build succeeded.

This corrects stale/mixed-generation readback, not requester scheduling, layout or full presentation.
It does not add background monitoring of a judgement while a screen is idle, a visual acceptance
result, new authorization logic or a new storage format. R2, R7 and R8 remained open at that
checkpoint; their current states are in the [review register](../judgement/the-judgement-store.md#authorization-correction-and-remaining-review-findings).
the subsequent R6 sizing correction and its remaining acceptance limit are recorded below.

The evidence expander carries the holder SID and scope, target identity, catalogue and generation
identifiers, contributing ACEs, uncertainty, preconditions and representative membership routes.
The [judgement-store document](../judgement/the-judgement-store.md#p-150-corrected--catalogue-2-2026-09-06)
records P-150's corrected domain-scoped Administrators classification and the real-reader lab
comparison. Historical results retain their recorded catalogue version; re-judge to obtain the fix.

**Documentation scope was corrected on 2026-09-06.** `ShellLayerTypesTests.AssetsFiles` previously
omitted `ControlEdgesSectionViewModel.cs`. Adding it before these entries made
`EachPageNamesEveryFileItsComponentIsScopedFrom` fail naming that file and
`TheAssetsPageTypesTableAndItsComponentAgree` fail naming both undocumented types. The other five
tests passed. The existing check now covers 34 assets-component types rather than 32; its parsing
and comparison rules were not weakened to accommodate the page.

### Requester sizing — R6

**Corrected and regression-tested; real-product visual validation is still outstanding.** On
2026-09-06 the owner reviewed the isolated made-up-data gallery comparison and accepted its sizing
for implementation. He plans subsequent forest testing on his small laptop screen and a monitor.
These checks belong to normal verification; the owner does not require a separate monitor-check
session before R2, R7 or R8 work continues.
That is preview/design approval, not evidence that the implemented product has passed those checks.
The Shell build marker is **AC**, so later screenshots can identify this implementation.

The defect was in the containing layout: the control table occupied an unbounded content-sized
row, while the requester notice, not a table, received the remaining height. Neither ObjectView
nor its Assets host provided section scrolling. A long control page could therefore put requester
answers below the reachable pane even though their table already had a maximum height.

The local section correction caps the control table at **240 WPF layout units**, retains the
requester table's **180-unit cap**, sizes the requester notice to its text, and adds vertical section
scrolling. WPF layout units scale with display settings; these are not fixed physical screen pixels.
Each table scrolls its rows; a short pane can scroll the section to reach notices, evidence and
requester answers. Small lists use only the height they need. This accepted nested-scrolling
trade-off follows Microsoft's [DataGrid sizing guidance](https://learn.microsoft.com/dotnet/desktop/wpf/controls/sizing-options-in-the-datagrid-control).
No data binding, coverage/failure wording, column, evidence access, paging command or data source
changed. No authorization, storage, schema or scheduling change is part of R6.

`ControlEdgeSizingTests` measures and arranges the real section/ObjectView XAML with the Assets
host's padding and column geometry, the product's theme dictionaries and real view models fed
synthetic results. It creates no application or visible window. Its **12 cases** cover populated
900-by-430, 1,300-by-650 and 1,600-by-900-unit panes, expanded evidence, empty/one/two-row requester
lists and requester-read failure beneath a full control page. Assertions measure row bounds,
generated last rows and their bound text, scroll extents, notices and evidence; binding checks alone
are not the sizing proof. Three in-memory negative controls remove the control cap, collapse the
requester table while leaving its maximum-height attribute, or remove section scrolling. Each must
make the same geometry assertions fail. These cases do not simulate physical monitors or certify
all column readability; the owner's actual laptop/monitor review remains necessary.

**Observed before/after:** after correcting harness setup, the unchanged selection ran **12 cases:
6 passed and 6 failed before production edits, then 12/12 passed afterward**. Five populated-pane
cases measured the unbounded control table at 1,300.29 units; the failure-notice case lacked the
section scrollbar. The regression source SHA-256 was unchanged between those runs. Initial harness
resource-loading failures are not counted as reproduction of R6. The broader layout, presentation,
Assets, R4, binding and resource selection passed **133/133**. The full `SecureAD.Next.Tests` project
passed **3,715/3,715**, none skipped, and the full solution build succeeded.

The separate gallery remains available as `SecureAD.Gallery --r6-preview`. It now labels its tabs
**Before R6 — reconstructed sizing** and **Implemented**; the first reverses only the three sizing
choices in memory, while the second uses the corrected product template. Both use made-up data;
navigation is a labeled placeholder and filters/paging are disabled. The no-window
`--r6-check <report-path>` compatibility check passed after implementation. No new visible window
was launched for the implementation checks, and no AD operation or retained-data readback ran.

R6's implementation is complete, not fully visually accepted in the real product. R2 scheduling,
R7 presentation, R8 reconciliation and P-145 were open at the R6 checkpoint. R2 integration and
R7 presentation were subsequently implemented, and R8 reconciles their current status below.
**Ordinary Shell/CLI re-judging still schedules no requester questions without an approved discovery
budget**, so obtaining the sizing or presentation fix alone cannot populate this table.

### R7 requester presentation

Following the completed performance comparison, the owner approved pausing further discovery tuning
and returning to the remaining product work. That checkpoint did not approve a presentation design;
the explicit continuation-session approval below did.
The later R2 schema-18 integration exists, but both hosts still pass no discovery budget; the
historical R6 statement above is not a claim that the automatic scheduler remains unimplemented.

Before this slice, the requester table showed requester, target, operation, authorization,
own-account, readiness and limits using internal enum names and a repeated common scope explanation.
Unlike the holder-edge table, it had no selected-row binding or accompanying evidence view.
That was the contained R7 presentation gap, not a reason to change the evaluator or enable scheduling.

**Approved design:** keep the existing table and approved R6 sizing. Use plain-language wording
for its separate answers, and add an expandable explanation for the selected requester assessment
beneath it. The explanation should show the stored identities, supporting permission entries and
holder/membership route, plus why authorization is unknown or the operation is not ready. Preserve
the distinction between authorization, the own-account restriction and readiness. Discovery-wide
coverage limitations remain separate from an individual answer; missing captured evidence,
unsupported analysis and processing stops must not be combined into a generic refusal.

**Practical trade-off:** the compact table remains scannable, but checking the proof takes selecting
a row and expanding its explanation. Showing all supporting evidence inside every row would make
comparison harder and consume the laptop's available height. The existing section scrolling and
table-height limits remain; no new screen or layout redesign is proposed.

**Approved in the continuation session:** the owner selected "Approve the recommended table wording
and expandable selected-answer evidence" after reviewing the plain-language design and its trade-off.
This supersedes the pending approval recorded at the checkpoint; implementation and validation are
recorded separately below. The R4 generation-bound readback and failure clearing, existing stored
answers and holder counts are preserved. No authorization, persistence/schema, budget, directory
access or laboratory operation is part of this slice. R7 real-product verification and final
feature acceptance remain open; the subsequent R8 correction reconciles status, not acceptance.

The owner requested a commit/push checkpoint and a new-session handoff before answering this
presentation proposal. It was unapproved at that checkpoint; the explicit answer above, not the
request to resume or create the checkpoint, supplies approval. The owner later explicitly requested
the R7 commit and push, completed as `a92d592`. The subsequent R8 instruction authorizes no new commit or push.

**Implemented and offline-validated.** The table retains all seven columns, its 180-unit height cap,
the control table's 240-unit cap and section scrolling. Authorization reads **Authorized / Not
authorized / Unknown**; the own-account answer reads **Own account only / Different account / Not
confirmed**; readiness reads **Ready from capture / Not ready / Unknown**. These are independent
translations of stored answers, never new permission calculations. Individual limitations now name
their specific missing evidence, unsupported analysis, processing stop or readiness blocker. The
common assumptions move into the evidence rather than being repeated in every table row.

The first stored requester answer is selected after generation validation; selecting another row
updates its proof. The expandable, read-only, copyable explanation includes requester/target/member
identities, judgement and derivation identifiers, Evidence fingerprint, captured time and account
flags, membership state, original supporting permission entries and direct/group route explanations.
Original SELF trustee identifiers remain beside resolved holders; permission order, masks, scope
flags, object-type fields and application bytes are shown as stored. No supporting entries is not
presented as a refusal. Unknown membership is not presented as non-membership. The explanation
states that this is neither a live-operation success prediction nor an established chain to Tier 0.
Capture-wide discovery notices and holder counts are not changed.

The explanation has its own 240-unit scroll area and is hidden without a selected answer. Selection
clears before every read, including paging, direction/filter changes and reconfiguration. Failure,
missing generations, mixed generations and empty products cannot retain old selected evidence.
New wording lives in `next/src/SecureAD.Shell/Resources/RequesterPresentation.resx`; no dependency or
public judgement contract was added.

**Validation:** the unchanged focused wording regression failed before the row-model change
(expected `Authorized`, actual `Established`) and passed afterwards. The presentation/readback/layout
selection passed **137/137**, including all current issue and route-reason translations, exact stored
identity/permission fields and preservation of R4 clearing. The real-template no-window layout suite
now has **19 cases**, retaining R6 coverage and adding selected-answer cells/proof at 900-by-430,
1,300-by-650 and 1,600-by-900 units, expanded-proof clearing after a failed read, and three in-memory
negative controls. Removing selection binding, removing evidence binding or collapsing the evidence
area each makes the same checks fail. No visible application window was launched.

Two low-severity test-setup findings were corrected, not counted as product reproduction: the
no-window table needed the existing R6 scroll/layout procedure to generate its last row; the
240-unit bound applies to the visible scroll area, not the longer text inside it. Neither correction
weakened the required row-content, selection, overflow or reachability assertions.

The full test project passed **3,837/3,837**, none skipped, and the solution build succeeded. The 137
focused tests also passed under code-coverage collection; its new report is
`next/.vs/R7-61e46dd999344a57bc8a79744f22a199/coverage.cobertura.xml`. No further performance experiment,
live-directory operation, protected-artifact access, frozen-evidence edit, commit or push was part
of this slice. Real-product laptop/monitor review remains unperformed, not accepted. R2 remains
inactive in both hosts without an approved numerical budget. The later R8 current-state correction
below does not promote these historical results into final feature acceptance.

### Requester workflow verification — R8

`SelfMembershipWorkflowTests` connects the stored product to this screen using newly generated
synthetic sealed evidence, real judging, `BundleAssetSource` and `AssetsViewModel`. Its target-first
and requester-first cases verify both own-account operations and independent readiness; selected
proof retains direct, global-group and SELF evidence. Re-judging to a no-scan generation clears old
selection, and malformed synthetic coverage clears requester proof while retaining valid holder
rows. Requester answers do not increase the screen's holder counts. R6/R7's real-template checks
remain the layout witnesses; the R8 workflow checks do not launch a visible window.

The current presentation has two separate levels: Shell completion and CLI summary state what the
capture-wide scan did, while this object section states whether selected requests were stored and
shows each answer's limits and proof. It does not add a browser of every discovery limitation.
No scan/no scheduled selection is not a refusal; unreadable data is not an empty successful read.
The [R8 reconciliation record](../judgement/the-judgement-store.md#r8-current-state-reconciliation)
owns the verification results and remaining gates. The documentation correction is complete for
the delivered scope; physical laptop/monitor and real-product verification remain outstanding
normal work. No new presentation, production limit or final acceptance was approved by R8.

### Password-reset permission

The owner approved the capability-first implementation and wording. `CanResetPassword` now appears
in the existing control table as **Password-reset permission**, with the existing evaluation and
expectedness columns. Its category is `CredentialExposure`, not permission-list takeover or a
classification of the target as Tier 0. The evidence states: **Permission evidence only. A password
reset and subsequent sign-in have not been tested.**

The label/category/caveat use `Resources/ControlEdgePresentation.resx`; the updated partial-scope
notice comes from Judgement's `Resources/ControlEdgeScope.resx`. The template, table sizing,
selection, paging and failure/generation safeguards are unchanged. Existing Self-Membership
requester details remain separate and their production discovery remains inactive. No password
action or new security finding was added.

`PasswordResetWorkflowTests` exercises real synthetic judging, persistence, both object-screen
directions, old-engine/category refusal and stale-proof clearing. Additional `ControlEdgeSizingTests`
cases bind the label and caveat through the unchanged real template at the three existing pane
sizes, without a visible window. The [judgement-store implementation record](../judgement/the-judgement-store.md#password-reset-control--bounded-implementation-preparation)
owns results and limitations. Introduced in schema 19 and retained in current schema 23; real-product visual checks
remain normal outstanding verification, not implied by these offline checks.

### Key-credential write permission

The owner explicitly approved the bounded implementation and wording before edits.
`CanWriteKeyCredentialLink` appears in the same table as **Key-credential write permission**.
Its resource-backed evidence identifies **Attribute: msDS-KeyCredentialLink.** and says
**Category: CredentialExposure; this does not classify the target as Tier 0.** The caveat is:
**Permission evidence only. A key-credential write and subsequent sign-in have not been tested.
This does not establish account takeover or a completed path to Tier 0.**

At the schema-20 checkpoint, the scope notice included this capability while retaining validated-write-only key-credential
access, ownership-derived control, replication, full-control aggregation and effective member
expansion as unfinished. Existing password-reset wording and requester distinctions are preserved.
No XAML, column, table sizing, paging, selection or readback-safety behavior changed.

`KeyCredentialLinkWorkflowTests` covers synthetic sealed-bundle readers, both directions,
expectedness/counts and old-engine/category/missing-proof refusal. Three additional
`ControlEdgeSizingTests` cases exercise the real template at 900-by-430, 1,300-by-650 and
1,600-by-900 layout units without opening a window. The
[implementation record](../judgement/the-judgement-store.md#key-credential-write-permission--bounded-implementation)
owns validation and limits. Re-judge to obtain schema 20/control engine 4; ordinary laptop/monitor
verification remains outstanding and is not a separate blocking session.

---

### Replication permissions

The owner approved the bounded implementation, wording and visible grouping. Schema 21/control
engine 5 adds **Secret-data replication permission** and **Filtered-attribute replication permission**
to the existing table. Evidence identifies **Naming context: {exact root DN} ({partition kind}).**
and **Category: ReplicationControl.** The caveat is **Permission evidence only. No replication
operation or credential extraction was performed. This does not establish account takeover or a
completed path to Tier 0.**

Non-collapsing groups are headed **Replication permissions — {holder} [{SID}; {scope}] — {root}**.
Other capability categories remain outside those groups. Groups cover the current page only and
the scope notice says so; the original page IDs, counts, expected filter and generation/failure
safeguards remain. A proven captured DC holder is labeled **Domain controller asset**; missing or
conflicting evidence is described as unconfirmed in selected evidence, not as a suppression reason.
Classification uses the existing DC signals without changing their use by other rules. The badge
requires a captured computer identity, readable UAC/primary-group values and agreeing signals.

The group collection is bound in the instantiated section's resources, not the template's shared
resources. Real-template tests exposed the latter as an empty-table defect and passed unchanged
after correction. No column or pane-size change was made. Six label/caveat sizing cases and an
actual group-header/item-count case join the existing no-window checks. The ordinary laptop/monitor
checks remain outstanding. The [implementation record](../judgement/the-judgement-store.md#replication-permissions--bounded-implementation)
owns validation and the remaining Stage 6 gates.

### Ownership permission control

Schema 22/control engine 6 uses the approved **Existing-owner permission control** and
**Owner-change permission control — not verified; not counted** labels in both existing directions.
The selected evidence retains the owner source, named modification, ordered permissions and each
independent prerequisite. The caveat is **Ownership and permission evidence only. No owner or
permission change was performed. This does not establish account takeover or a completed path to
Tier 0.** The layout and page-local replication groups are unchanged.

Only established existing-owner capabilities are counted. Blocked/unknown owner assessments are
uncounted detail; missing ownership evidence still makes coverage incomplete. Accepted and
proven-deleted owners do not produce ownership edges. Owner-change compounds retain 0103's Unknown
laboratory gate. Real-reader tests cover both directions, stale versions and damaged-proof clearing;
six real-template sizing cases cover the two labels at the existing sizes. Normal laptop/monitor
checks remain outstanding. The [implementation record](../judgement/the-judgement-store.md#ownership-control--bounded-implementation)
owns verification and limits.

### Full-control permission summaries

The owner approved the bounded recommendation, then requested implementation. Schema 23/control
engine 7 adds **Full-control permissions** assessments to the same object-first and named-holder-first
table, with a visible **Count status** column. Established summaries say **Counted once**;
their supporting permission rows say **Included in full-control count — not counted again**.
Primitive evidence and categories remain visible, including both separately named replication
capabilities in their page-local holder/root groups. Existing-owner control retains its independent
count; owner-change and requester assessments retain their uncounted boundaries.

The headline explains: **Counts include established full-control summaries instead of their
supporting permissions. Unknown full-control assessments add no count. Other unknown candidates
retain their existing counting behavior.** Broken/Unknown summary evidence states that surviving
permissions remain visible and, where eligible, counted separately. Unknown assessments remain
unanswered coverage, not a complete negative answer. Expectedness still has its own column/filter
and a stated hidden count.

Both directions consume stored assessments/support links and a common combined paging cursor;
no authorization is recomputed in the screen. The source lists retain original ordered permissions
and alternative grants under **Supporting permissions and alternative grant routes**. A stored
independent-route witness uses **Removing one complete grant route alone leaves another route to
full-control permissions.** The caveat is **Permission evidence only. No directory operation was
performed. This does not establish operation success, account takeover or a completed path to Tier 0.**

The count cell wraps; the existing table and evidence-height bounds, selection and generation/failure
safeguards remain. New real-template tests verify the summary, support count text, header and long
read-only proof at the three existing sizes. A deliberately unbound count-status cell makes the
check fail. These are no-window synthetic checks, not acceptance of ordinary laptop/external-monitor
verification. The [implementation record](../judgement/the-judgement-store.md#full-control-aggregation--bounded-implementation)
owns the final suite/coverage results and remaining Stage 6 gates. That full-control slice added no
live directory operation, discovery enablement or effective member expansion; the subsequent bounded
member-attribution presentation is described below.

### Stored group-member attribution

The accepted member presentation is implemented over judgement schema 24/control engine 8 and
Derivation schema 11 inputs. Selecting a source permission in either existing direction exposes
**Members of the permission-holding group**. Counts distinguish resolved members, unresolved identities
and unconfirmed membership candidates; a partial expansion states that these are not total effective
membership counts and names missing evidence or the configured stopping budget. Counts describe
principals, including nested groups, not a user-only workforce total. The source permission remains
counted at its holder, regardless of member or route volume.

Stored representative chains are grouped by initial membership under **Membership routes — grouped
by initial membership**. Primary-group links and disabled accounts are identified. The route caveat
does not promise every path was enumerated or that removing displayed memberships removes all access.
Member paging reads stored rows; opening or paging a screen never starts expansion or contacts a DC.

**Permissions through group membership** is a separate reverse source-permission view. Its capability
text retains the original permission's evaluation and count status, including Unknown/uncounted
owner-change control and **Included in full-control count — not counted again**. Membership and group
usability do not establish a complete requester access check. Expected source counts remain stated
when hidden, and partial selection coverage is not presented as a complete total.

Not-run, unresolved-holder, incomplete and corrupt evidence have distinct notices. Generation changes
and member-proof failures clear the affected member detail rather than inventing an empty answer;
independently valid holder counts remain visible. With no approved budget, the notice states that
member expansion did not run. Both production hosts remain inactive for member expansion and requester
discovery. Real-template checks at 900×430, 1300×650 and 1600×900 and the deliberately unbound member-cell
control are synthetic verification, not physical laptop/external-monitor acceptance. The
[member-attribution implementation record](../judgement/the-judgement-store.md#bounded-effective-member-attribution)
owns final results and remaining gates.

## Nothing on this screen is ever established-bad

Every fact is drawn in one of three states, per
[`0056`](../../decisions/0056-the-visual-language-encodes-three-states.md), and the tree, the object
listing and the attribute values only ever reach two of them: established, or unknown. A tree node
does not grade the container it names, and an attribute value does not grade the value it shows.

The judging is the only thing in this product that says something is wrong, and it says it as a
finding. A column an administrator reads as a verdict, filled by anything other than a rule that ran,
is the worst thing this screen could do.

---

## The findings and the evidence fail separately

`Refusal` is about the bundle. `FindingsRefusal` is about the judgement beside it. They are separate
files with separate remedies, and a bundle can be read perfectly with no judgement next to it at all.

Telling an operator his evidence could not be opened, when the truth is that the judgement could not,
sends him to re-capture a forest for nothing.

The same distinction runs one level deeper, in the grid itself:

- **A bundle nobody judged is refused, not shown as a clean forest.** An empty list means nothing on
  its own, so the judgement layer hands findings out beside the rules that ran.
- **A judging that ran and matched nothing says so**, which is a different fact and a good one.
- **An empty *filtered* grid says nothing matched the filters.** Empty with no filter is about the
  directory; empty with a filter is about the question. Stating the first while the second is true
  would tell an operator his container is clean when he has narrowed to a severity that happens to be
  absent.

---

## The findings are scoped by the same selection as the objects

The container selected in the tree scopes both lists. An operator who selected `OU=People` and
switched to findings is still asking about that container, and a grid that widened to the forest
would answer a question he did not ask.

That state is held once, on the screen, rather than once per list — two selections that can disagree
is a defect waiting for the day they do.

---

## The grid pages forward, and remembers where it has been

Findings are read a page at a time by `JudgementReader.ReadPage`, which is described in
[`the judgement store`](../judgement/the-judgement-store.md). What that costs this screen is that
**paging only goes forward**: a page knows where it ended, not where the one before it began, so
stepping back means keeping a stack of the marks already shown. The alternative is an offset, which
is the expense the paging exists to avoid.

**Changing a filter empties that stack.** A different filter is a different list, and a mark taken
from the old one points into rows the new one may not contain — so the grid would open part way down
a list that no longer exists, with no way back to the top.

---

## What the filters offer is read, never listed

The severities and rules a filter shows are the ones some finding on this run actually has. A list
written into the screen would offer Critical whether or not anything is critical, and an operator who
picks it and gets an empty grid has learned only to distrust the control.

They are read once for the run rather than per selection: they describe the whole judgement, and
scoping them to the selection would make a chosen filter vanish from its own list on the next click.

---

## Opening an object replaces the grid, and the tree stays

The predecessor used a left pane and a pop-out window, both because two panes left no room for an
entry table on a laptop. Here the object takes the grid's place — but the tree remains, because an
operator reading one object's permissions is still somewhere in the directory and will move to a
neighbour next.

**Double-clicking a finding opens the object it is about, on its findings section.** The finding
names a distinguished name; the screen opens that object the same way the listing would, so there is
one path to an object and not two.

**Closing an object leaves the findings alone.** The grid is not reloaded on return, so the operator
comes back to the page he left rather than to page one — which after a long scroll is the difference
between navigation and punishment.

---

## Which sections an object has is decided by its class

`ObjectSectionCatalog` maps a class of object to the sections it has, and the list is driven by the
class and never by whether a value happened to arrive. An object whose account attributes all failed
to read still has an Account section — saying the values are missing — because a section that
disappears when its contents fail is a screen quietly reporting *nothing to see*.

A section that is named but not yet built says so, rather than rendering empty. And a section a class
does not have leaves the operator's selection alone rather than resetting it, so moving between two
objects of different classes does not throw away where he was reading.

`ObjectSectionCatalogTests` holds every attribute a class justifies to a section that claims it, so
curation cannot hide a value the capture actually collected.

---

## A selected finding says what it means and what to do about it

Below the findings grid sits a panel carrying two blocks for the selected row: **why it matters** and
**what to do**, with the Microsoft page the reasoning rests on when one is recorded. They come from
`RuleGuidanceCatalogue`, looked up by rule identifier, and are described in
[`what a finding is`](../judgement/what-a-finding-is.md).

**A grid that says what is wrong and leaves the operator to work out what to do is half a product.**
The owner's decision of 2026-09-01: this is a working surface administrators clean up from, not a
preview of a report.

**It binds to a `SelectedFinding` property, not to the collection's current item.** The current-item
path reads as a property name to `ViewBindingGateTests`, so a binding through it is one no gate can
resolve — and a view naming something no view model publishes is how this shell crashed once with the
build green, which is why `ViewResourceGateTests` exists. The same shape is already used by the run
library and the object sections.

**A rule with no guidance says so.** A stored judgement outlives the build that made it, so a bundle
can carry a finding from a rule this build no longer runs. The panel then states that no guidance is
recorded rather than showing an empty box, because blank space where an explanation belongs reads as
*there is nothing to say about this* — a different claim, and the wrong one, per
[`0002`](../../decisions/).

**What it must never say is that the finding is now resolved.** That is a claim about every route to
the object, which the judgement half must prove rather than assert. The wording is held by
`RuleGuidanceTests`, which fails the build on copy that goes further.

---

## Membership evidence stays with one finding

**Membership detail under `0108` is built on both finding surfaces.** The selected finding panel and
an object's Findings section each have a **View membership evidence** expander. It shows one block
per initial membership, with the reached roots, captured names, scoped identifiers and supporting
chains beneath it. Primary links, distribution paths, unknown group types and direct catalogue
protection are stated explicitly. This adds detail, not finding rows. Partial summaries name their
limits, say the displayed count is not a total, and prevent the finding row from showing complete
coverage. The text does not promise a minimum set of removals or elimination of other privilege.

`MembershipEvidencePresentationTests` exercises the wording; `ViewBindingGateTests` checks the
exact bindings in both real templates. Disconnecting the findings detail binding and, separately,
the object completeness binding was observed failing with the missing property named.

## The rules tab says what was checked, which no findings grid can

The fourth tab under Assets lists **every rule this build ships**, each with what it looks for and
what it did to the run being read. It is the only place in the product where the description of a
check is reachable without a finding to hang it on, and that is what closes `P-118`: the same words
sat under the findings grid, so on a forest with nothing wrong with it they were on no screen at all.

**The catalogue is the list and the judgement only annotates it.** `AssetsViewModel.ListRules` walks
`RuleCatalogue.All` and looks each rule up in what `ReadRuleExecutions` returned. Built the other way
round, a rule the judging never scheduled would be absent — and a rule missing from a list of rules
reads as a rule that does not exist. An execution naming a rule this build no longer ships is
appended afterwards rather than dropped, because a judgement outlives the build that wrote it and
dropping the row would quietly shrink the account of what was done to the bundle.

**Four different things draw an empty findings grid, and this tab is where they are told apart.** A
rule that judged every object it was about and reported nothing; one that could not read what it
declared; one that failed; one that was never scheduled. `RuleRowViewModel.Outcome` states which in
a sentence — *judged 2,082 objects and reported nothing* is a coverage claim, and the indeterminate
wording names the attribute that was missing and says the result is a floor rather than a total.
`RuleRowViewModel.State` marks a rule that found something as established-bad rather than a fault:
the rule did its job and the forest is what is wrong. `FactState.Fault` is kept for the rule itself
failing, which is a defect in the product.

**It is not scoped by the tree, and the screen says so.** A rule is a question asked of the whole
forest, so `ListRules` runs when the tab is chosen and when the run is read again, and not on any
selection or level change. Narrowing it would put *judged 2,082 objects* beside a container the
judging never counted separately.

**A judgement that will not open is a sentence, not a silent list of rules that did not run.** Those
are opposite facts calling for different actions, and the second wording would state that nobody
judged the bundle while the truth is that its judgement is unreadable.

---

## What this page does not decide

The three-state visual language, what the product calls a finding, and whether an accepted finding
stays visible are all decided in
[`how results are shown`](../../areas/how-results-are-shown.md) and the records it names. Where this
page and a record disagree, the record wins and the disagreement is a defect.
