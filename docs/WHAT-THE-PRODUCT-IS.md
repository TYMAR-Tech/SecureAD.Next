# What SecureAD is

An Active Directory security audit tool. **It reads a forest once, seals that reading as evidence,
and everything it says afterwards it says from that file.**

The product makes two separable claims, and keeping them separable is the whole design:

1. **This is what your directory said, at this moment.** Provable years later, on a machine that
   never saw the forest.
2. **This is what we conclude from it.** Re-runnable under better rules without touching claim 1.

**This is orientation, not authority.** Nothing here states the product's position; only a record in
[`decisions/`](decisions/) with `Status: Accepted` does that. Where this file and a record disagree,
the record wins and this file is wrong.

## The shape of a run

| Stage | What happens | State |
|---|---|---|
| Connect | Find the forest itself; climb an ordered ladder of protection and record which rung each controller answered on | built |
| Preflight | Prove a controller can serve what it will be asked, before the run commits | built |
| Capture | Read objects, permissions, group memberships, schema, extended rights, SYSVOL/GPO files | built |
| Reconcile and seal | Reconcile referrals with authorized scope, record uncertainty, then fingerprint immutable Evidence | built |
| Derive | Compute reusable cross-object facts into a disposable store beside Evidence | built; group expansion, membership cycles and AdminSDHolder products persisted and readable |
| Judge | Stream the bundle once for object rules, then publish saved path qualifications as findings in a separate store | built, 20 rules |
| Read back | Run library, directory tree, object detail and findings | built |
| Dashboard | Coverage and inventory: how much of the forest was read, and what it held | built |
| Reports, compare and export | — | not built |

**The counts and states in that table are checked rather than maintained by hand.**
`StageStatusGateTests` holds each state to a witness — a type that exists if and only if that stage
is built — and asserts both directions, so a stage cannot be quietly finished any more than it can
be claimed early. The rule count is checked the same way, and `next/tools/check-stage-status.ps1` is
the same check as a diagnostic a person can run. A status goes false when the code moves and the
document sits still, so it cannot be protected by proof-reading; this file claimed *two rules* for
long enough that twelve more were built underneath it. **Until 2026-09-12 this paragraph overstated
itself**: eight of the nine states above were unchecked while it said they were not, which is the
shape this repository rates worst. See `P-135`, and `ROADMAP.md` § *Where we are* for the per-stage
witnesses of the build order, which are a separate table answering a separate question.

`0008` fixes the boundary: **the only component that touches a domain controller is capture.** A
screen showing a permission is reading a file, not asking the directory.

**The application is the product; the command line runs unattended.** The owner's words, 2026-08-26:
*"this whole app is a GUI, the cli is just to capture overnight."* The GUI is where an operator
works and is what every screen is designed for. The command line exists so a long run can happen
overnight without the application open, and **it is intended to grow judging too** — the owner,
later the same day: *"i will be making it so the user can run the audit and it complete the judging
via CLI, so it can run overnight."* So the command line is not capture-only forever; it is the
unattended path, and the GUI is the worked path.

## Fix and feature priority

**Owner-approved checkpoint integration before the Stage 6/7 correction, 2026-10-08.**
The owner approved committing the completed shared-proof correction separately, addressing the
three reproduced verification failures without weakening their checks, and merging `rules-delivery`
to `main` once the exact committed candidate passes CI.
The merge also carries the branch's already committed SEC-026 and SEC-083 capture changes.
Keep `rules-delivery`, update it from the merged main and continue in this same checkout without
another worktree; preserve unrelated diagnostic work rather than including it accidentally.
This authorizes the checkpoint commits, push, pull request and verified merge, not production
acceptance, package replacement, live access or a production judging rerun.
Keep the proposed Stage 6/7 correction and its new measurements out of this integration checkpoint.
The bounded verification correction appends the missing Evidence-14 coverage-identity pin without
editing versions 6-13, and makes the three SEC-083 nullable parameter choices explicit at their
call sites without changing scan behavior or weakening the architecture gate.
All 132 focused checks pass with coverage, and all seven required cases detect five isolated
rebuilt defects with five passing rebuilt controls; the active checkout never carries those defects.
The [integration verification record](../.v-merge-ready-20261008-9c35/handoff.json) retains the
source/binary fingerprints and outcomes; a correct-source full regression and exact-head CI
remain mandatory before the authorized merge.

**Owner-directed Stage 6/7 and whole-pipeline design review, 2026-10-08.**
After the shared-proof correction, the owner rejected alternating isolated speed and storage
fixes and requested a fresh-session handoff for one objective assessment of the whole design.
The assessment must examine whether Stage 6 target admission and Stage 7 path/requester analysis
are semantically correct and appropriately scoped, including depth, cycles and question breadth,
rather than treating them as settled while focusing only on storage.
His recollection of the predecessor's depth-five limit is a question to assess, not approval to
introduce that limit in the rebuild; the accepted backwards supported-path calculation has no
arbitrary security-depth cutoff, and the two applications' path models are not interchangeable.
Start with a read-only review of the normal reachable pipeline, distinguish active work from
disabled expansion/discovery features, and account for processing, memory, storage and readback
together before proposing another implementation or measurement campaign.
The [fresh-session handoff](../.v-shared-path-20261007-7f2c/STAGE6-STAGE7-DESIGN-REVIEW-HANDOFF.md)
records the code, passed depth/cycle witnesses, production scope/cost counters and remaining
questions; it does not declare Stages 6/7 complete or production-accepted.
Preserve all existing work and evidence, with no new depth/processing cap, live access, production
rerun, package replacement, commit or push authorized by this review request.

**Shared-proof storage correction implemented and offline verified, 2026-10-08.**
The [validated checkpoint](../.v-shared-path-20261007-7f2c/handoff.json) records Judgement format 62,
with Evidence and Derivation unchanged by this correction, every saved answer and occurrence
preserved, and no UI wording/layout change or additional analysis scope.
Identical proof components are shared within their exact generation/context; original permissions
reuse the existing shared-entry store, and ordered use-site references retain resource, position
and source bindings.
The calculation header now binds separate selection records and existing uncertainty rather than
embedding them, and normal GUI/CLI completion uses saved counters instead of reconstructing all
requester proofs.
Selected-page reconstruction reuses validated components only within that read/page lifetime,
never across later reads or generations; explicit full-detail verification remains separate.
All 463 original lab source proofs and the full saved input/selection collections match their
frozen canonical fingerprints after roundtrip, and the owner's new lab passes normal protected
readback as recorded below.
The full solution rebuilt successfully; 7,420 of 7,423 tests passed with coverage, with exactly
three failures independently reproduced on the untouched baseline, while all 34 required behavior
checks detected 24 rebuilt defects with restored controls.
The full-size synthetic case completed actual writer publication, index construction, checkpointing,
sealing and saved readback for 939,225 nodes, 653,689 questions and 1,586,470 uncertainty records.
Its database finished at 13,580,939,264 bytes with a 2,495-byte calculation header and sampled
25,089,148,257-byte peak working files, against generated expanded source/header contents of
47,295,959,913 and 18,143,455,537 bytes respectively.
This is a proof-heavy persistence test with fabricated source bindings, not a new forest capture,
permission calculation, full production table reconstruction or production-capacity/runtime claim.
The combined reference-sizing/selection-persistence phase was costly and remains a separately
recorded profiling followup; further optimization or production execution still needs its approval.
Original lab bundles, production reports, existing work and historical verification records remain
preserved, with compact source/binary/measurement records retained instead of disposable bulk.

**Owner-provided current-format lab verification and proposed capture head start, 2026-10-08 UTC.**
The owner supplied `ad.lab-20261008-034144`, produced by his build containing the shared-proof changes,
for offline inspection while the full-size synthetic capacity run continues.
The original bundle remains untouched; a verified copy passes normal saved-result readers with
Evidence 14, Derivation 16 and Judgement 62, including all 463 saved requester questions and their
route views, exact source-generation bindings and explicit unknown authorization results.
The executable hash matches the local published package and the logged engine identity is tied
through its matching PDB to the current source documents, not inferred from the `d187528` stamp.
The owner is considering taking that build to production for a new capture; this is not an
authorization for agent live access or package replacement and is not production-capacity acceptance.
The recommended head start is the existing CLI `--capture` mode, which seals evidence and stops
without derivation or judging, leaving the owner in control of when analysis begins.
A new Evidence-14 capture avoids the separate older-Evidence-13 delivery issue; it is not a
recapture requirement imposed by the Judgement storage correction itself.

**Owner-approved shared path-proof correction for the next implementation session, 2026-10-07.**
Following the production publication disk failure and read-only proof trace, the owner approved
saving identical immutable proof components once, with ordered occurrence references retaining
each question's saved answer, original permission positions, requester, resource, membership
assumptions and exact Evidence/Derivation/Judgement bindings.
Replace the oversized calculation header with a compact manifest over separately saved selection
records and the existing input/uncertainty records; update coupled writers, validation, selected
proof/route/finding readers and GUI/CLI completion coverage so summaries do not reconstruct every proof.
Preserve every limitation and its detailed evidence, group-held counting, passive readback and
atomic publication; this changes storage, not ownership, permission, operation or path semantics.
The accepted cost is a new Judgement format with strict reference validation, no migration and no
parallel legacy production implementation; UI wording and layout remain unchanged.
The approved offline verification includes exact saved-answer comparisons, corruption and
resource/generation substitutions, isolated explicitly rebuilt defects and restored controls,
and a synthetic capacity runner covering the observed nine-domain workload of 939,225 nodes,
653,689 questions across the three existing families, 359 selection resources, 138 fixed targets
and 1,586,470 uncertainty records, with high-, low- and no-sharing controls.
Measure index construction, checkpointing, sealing, reopening and peak database/WAL/temporary
storage as well as final size; lab content repetition is not a production savings forecast.
Fingerprint comparison sources and binaries rather than treating the production executable's
`9621ea0` version stamp as all compiled source: the identical lab/production executable logs and
saved lab format 60 establish later compiled features, but not an exact production source manifest.
This approval is for the next bounded implementation session, not an implemented correction or
production-capacity acceptance, and does not authorize live access, production judging, package
replacement, analysis expansion, truncation, processing caps, commit or push.
Preserve the existing checkout, owner work, original lab bundle, production reports and historical
verification records; use isolated lab copies and synthetic inputs only.

**Owner-approved SEC-026 implementation and Microsoft verification, 2026-10-07.**
The owner approved the proposed bounded duplicate-SPN rule on `rules-delivery`, with fixed High
severity, and required the proposal to be checked against Microsoft documentation before delivery.
Compare complete captured SPN values case-insensitively across the one captured forest, retaining
ports, instance names, service-name suffixes, original occurrences and distinct GUID-based owners;
do not exempt identical HOST/RestrictedKrbHost values or turn repeated values on one owner into duplicates.
Persist one finding per affected owner with all known matching owners, and keep known duplicates
when missing evidence prevents a complete inventory; neither finding absence nor recorded attribute
values prove live authentication, complete attribute visibility or takeover.
Microsoft's MS-ADTS uniqueness constraints distinguish exact values from alias checking; this
bounded delivery does not compare sPNMappings aliases or other forests and must say so.
New guidance explains authentication-name conflicts, requires confirming the intended service owner
before removing an erroneous registration, and warns against removing Kerberos system registrations.
High severity and per-owner finding grouping are approved product choices, not Microsoft ratings.
Sources checked: [SPN format](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/cd328386-4d97-4666-be33-056545c1cad2),
[uniqueness constraints](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/3c154285-454c-4353-9a99-fb586e806944),
[setspn and Windows case behavior](https://learn.microsoft.com/windows-server/administration/windows-commands/setspn)
and [duplicate-SPN troubleshooting](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/kerberos-error-kdc-err-s-principal-unknown-or-not-unique).
No live query, production-audit change, new capture requirement, package replacement, commit or push
is included in this rule implementation authorization.
The [SEC-026 checkpoint](../.v-sec026-20261007-67ac/handoff.json) records a successful full solution
build and 550 passing affected-area tests with coverage after the final correct-source rebuild,
with 1,030 matching code/configuration inputs and all 54 required checks detecting rebuilt defects
across 17 variants with restored controls.
The final run uses CI's noncompeting test-collection setting; preceding parallel-run UI/logging
timeouts remain recorded rather than described as a successful run.
Normal GUI and CLI judging now schedule SEC-026 during the existing captured-object pass and
publish its full-value duplicate assessment afterward; saved readback validates typed owner/occurrence
evidence against the selected evidence seal and judgement generation without rerunning analysis.
Judgement format 61 stores this evidence; Evidence and Derivation remain unchanged, so judging the
owner's completed sealed capture can add SEC-026 without another capture.
The owner's in-progress production run and existing package were not changed, and lab/display/
production acceptance remains outstanding.

The owner subsequently requested committing and pushing SEC-026 on the existing rules branch
and providing a new-session handoff for the next rule; this does not approve SEC-083's proposed
Critical severity or implementation scope, replace the production package, or authorize a merge to main.

**SEC-083 is an opt-in capture, disabled by default, 2026-10-07.**
The owner chose the predecessor's model for Group Policy Preferences password detection: checking
every XML file beneath every GPO adds too much recurring SYSVOL capture time for one legacy
condition that a customer can check deliberately once, then normally leave disabled on later
audits if the environment was clean.
Enabling the option scans for non-empty `cpassword` occurrence metadata and preserves known
occurrences beside explicit enumeration, read and parse gaps; disabling it must record that
SEC-083 was not scanned and must never turn finding absence into a clean verdict.
The ordinary SYSVOL capture remains enabled for its other evidence, and neither a previous clean
scan nor a disabled later scan proves that no policy changed between captures.
The owner approved placing an unchecked **Optional SYSVOL check** in the existing **Scope you are
authorizing** card, never remembering the choice between audits, with the label **Scan Group
Policy XML for legacy stored passwords** and wording that states the recursive cost and that
disabled means **Not scanned**, not **Passed**.
The unattended equivalent is `--scan-gpp-passwords`.
Implemented and offline verified on `rules-delivery`: ordinary captures no longer enumerate or
read XML files for this check, while an opted-in capture retains occurrence metadata and records
`NotRequested`, `Read`, `PartiallyRead` or `Unreadable` independently for every policy.
Evidence format 14 stores that capability-specific coverage; the full solution rebuilt
successfully, 346 focused tests passed with noncompeting test collections, and four isolated
rebuilt defects were detected before a forced restored-source rebuild passed.
The first attempted restored control reused mutated incremental-build output and was rejected;
forcing `Rebuild` established the accepted provenance.
Finding wording, file-level grouping and severity remain approval-gated, and the owner's running
production audit and package were not accessed or changed.

**Owner-directed rule delivery during production acceptance, 2026-10-07.**
While the owner-operated production audit runs, the owner requested the remaining-rule inventory
and practical implementation groupings, and wants rule work to proceed on one branch in the
existing checkout rather than creating separate trees.
The local `rules-delivery` branch was created in the sole active `SecureAD.Next` checkout, carrying
existing uncommitted governing-document updates without altering the production package.
This supersedes waiting for the running audit to finish before preparing rule delivery; production
acceptance remains open, and individual rule severity, scope and evidence-extension decisions in
the reviewed handoff remain approval-gated rather than implicitly accepted.
All 13 retained rule-handoff documents were verified against their saved SHA-256 manifest before
planning; the migration map is a proposed disposition, not a requirement to create every old ID.

**Owner-started production audit and cleanup pause, 2026-10-07.**
The owner reports a new production audit running with his latest build and expects it to take
many hours; he directed stopping local cleanup for now and requested the remaining application
work to be laid out.
This records an owner-operated run in progress, not verified executable provenance, successful
completion or acceptance of the saved results, and grants no agent access to the production forest.

**Owner-approved project TEMP followup, 2026-10-07.**
The owner approved cleaning verified SecureAD temporary leftovers from `C:\Temp` and the user
TEMP directory while preserving unique lab/performance inputs and unrelated applications' files.
The [completed pass](../.v-temp-inventory-20261007-663a/cleanup-result.json) removed 13.96 GiB of
identified synthetic tests and empty directory trees, retaining available reports and leaving
2.96 GiB of unclassified project/lab/benchmark/package contents plus junctions for separate review.

**Owner-completed folder rename and stray-folder cleanup approval, 2026-10-07.**
The owner renamed the independent active checkout from `SecureAD.Next-stage7` to `SecureAD.Next`;
its branch remains main and its Git storage remains local and independent.
He then approved inspecting and cleaning the previously uninventoried sibling
`SecureAD.Next-stray-2026-09-30`, preserving useful measurements and unique inputs rather than
deleting its 50.58 GiB by name; the empty followup directory was removed non-recursively.
Historical stage7 absolute paths refer to the same checkout before this rename.
The [stray cleanup](../.v-stray-cleanup-20261007-4f82/cleanup-result.json) subsequently reclaimed
41.45 GiB, retaining 9.13 GiB of unique material under `next/artifacts/retired-stray-20260930`
with a hash-verified duplicate mapping; both obsolete sibling folders are now removed.

**Owner-authorized reconciliation and main integration, 2026-10-07.**
The owner requested reconciling uncommitted/unpushed work across the local checkouts and merging
the current good build to main before further repository cleanup.
Preserve the older dirty working trees while accounting for their contents; duplicated corrections
already present in the current build need no second implementation, and stale status wording or
local-only tool configuration must not replace current product decisions.
This authorizes branch integration, commit, push and pull-request merge, not package replacement,
live directory access or a new claim of lab/production acceptance.
After a successful merge, the owner explicitly selected keeping only `main` locally and on GitHub
and moving the active stage7 checkout onto `main`.
Delete obsolete branch references only after their commits are confirmed retained by main;
preserve unique working-tree files and the compact reconciliation record before handling older
linked checkouts, and do not confuse deleting a branch name with deleting its checkout or evidence.
PR #5 merged as `4734ba7` after all 7,328 clean-machine tests passed at `f210957`, with only
test-host corrections beyond the accepted application build.
The stage7 checkout is now on `main`; all other local and GitHub branch names were removed only
after ancestry checks confirmed their commits remain in main history.
The two older linked checkouts remain on their original detached commits with their uncommitted
files preserved and hash-verified; deleting their directories remains a separate cleanup decision.

**Owner-authorized source checkpoint and local artifact cleanup, 2026-10-07.**
The owner requested committing and pushing the completed work, then reducing local project storage,
estimated by him at 400-500 GB, rather than retaining every historical verification artifact.
He subsequently approved making the active checkout independent, consolidating a compact useful
performance reference set, removing reviewed generated bulk and retiring the older checkouts.
Future runs should retain compact results and reproducible workload definitions by default, not
every intermediate database or failed attempt; unique real inputs and frozen correctness anchors
remain distinct from disposable benchmark output.
He authorizes consolidating relevant history and discarding material that has no continuing value,
with particular care for evidence needed by future performance investigations.
Inventory actual paths and sizes before deletion; retain unique source, frozen correctness anchors
and performance evidence needed to explain or reproduce meaningful comparisons, rather than
preserving every copied build, synthetic test database or failed attempt by default.
This changes the earlier blanket retention direction for local disposable artifacts; it does not
authorize deleting valuable capture evidence without identifying it, changing measurement results,
or publishing private evidence with the source checkpoint.
The owner extended read-only inventory to all three SecureAD.Next checkouts and project-linked
temporary folders, leaving the predecessor and unrelated temporary files outside scope.
He then explicitly approved the first disposable-TEMP list: the
[completed cleanup](../.v-local-cleanup-20261007-c00a/cleanup-result.json) removed 98.19 GiB of
generated verification data while preserving its reports/provenance and all performance campaigns,
captures, packages and source checkouts.
Deleted temporary paths in historical verification records are now provenance, not promises that
their generated test databases still exist; the original measurements and records were not rewritten.
The subsequent [repository consolidation](../.v-repository-consolidation-20261007-a118/cleanup-summary.json)
made the current stage7 checkout independent and reclaimed another 101.86 GiB without changing
application/test/tool sources, for 200.05 GiB reclaimed across both cleanup passes.
Retained original inputs, raw traces, reports, fingerprints, source snapshots, packages and the older
working files are now under `next/artifacts`; its [history index](../next/artifacts/history-index.json)
maps retired paths and explains which paths in old records are historical rather than still-present outputs.
The retained historical tree is 40.96 GiB, not a new claim that every remaining byte is permanently required.
The former original-checkout path now holds only a relocation marker for this VS Code session,
and the followup has no files but retains an empty directory held open by Windows.
Open `SecureAD.Next-stage7` as the VS Code folder; its main history, full solution build and 229
architecture/frozen-hash checks were verified after retirement.

**Owner-requested New audit wizard preview, 2026-10-07.**
While testing the connected Tier 0 presentation in the laboratory, the owner requested a fictional
mockup of improvements to the New audit screens.
The [interactive wizard preview](../.v-ui-audit-preview-20261007-c493/audit-preview.html) retains
the existing two-step structure, makes blocking readiness issues visible above the domain table
and beside Next, keeps all-domain details together, and separates capture-only from capture-and-analyse.
Review becomes the progress/outcome surface rather than introducing another approval screen;
sealing, derivation and judging retain separate outcomes, including stopping after evidence is sealed.
The owner approved implementing the wizard presentation on 2026-10-07 while testing the Tier 0
changes in the lab; that authorizes the revised wording/layout, not changes to capture behavior,
protection requirements, scope defaults, budgets or packages.
The existing recovery contract still applies: Next rechecks every domain, even after a refusal,
so the presentation must not disable the only action capable of clearing an old preflight failure.
The [wizard-presentation checkpoint](../.v-audit-wizard-20261007-d916/handoff.json) records 572
passing affected-area tests with coverage after a final correct-source rebuild, 1,026 matching
code/configuration inputs and all 22 required new/adapted checks detecting rebuilt defects across
15 variants with restored controls.
The application retains the two steps with a compact step strip, a persistent preparation warning,
all-domain details, existing attested exclusions and expandable controller overrides.
Capture-and-analyse and capture-only remain distinct choices; activity uses existing reported
phases/counters and elapsed/update-age values, with capture and sealing grouped where the launcher
does not supply separate completion signals rather than inventing a sealing percentage.
Output cards distinguish sealed evidence, saved/degraded/failed/stopped analysis and analysis not
requested; stopping an active audit asks for confirmation, while canceling preparation remains
its existing separate action, and already-sealed evidence remains available after analysis stops.
Lab packages were not replaced; representative lab, physical-display and production acceptance
remain outstanding, and no capture behavior, scope default, protection requirement or budget changed.

**Owner-requested Groups browsing mockup, 2026-10-06.**
After SEC-052, the owner requested a Groups view like the predecessor's inventory to help an
administrator see their groups, with double-click opening the corresponding object.
Inspect the predecessor read-only for the interaction, then provide a fictional-data visual mockup
using the current product's presentation; this is preview approval, not implementation approval.
The proposed placement, counting labels, coverage/cycle separation and return-navigation behavior
remain for owner review, and the predecessor's live checks, SID-only object lookup and window
architecture are not adopted by this request.
The owner liked the preview and explicitly approved implementation: Assets > Groups, the current
blue-grey presentation, group search/scope/type filters, separate direct/known-total/cycle/coverage
information, selected-group context where space permits, and double-click or Enter to open the
captured object with return navigation preserving the list state.
Implement against saved, generation-bound evidence and derived results, not live queries or
analysis replay while browsing; missing totals and unresolved references must remain explicit.
This approval does not authorize changing production budgets, performance campaigns, package
replacement, commit or push, and does not count as physical-display or production acceptance.
After source inspection found that no matching structural nested total is saved today, the owner
selected browsing first, then saved nested totals as a separate bounded pass.
The first delivery must provide the group list, direct recorded membership, cycle information and
captured-object navigation, with an explicit "Not available" total rather than relabelling the
authorization expansion or doing new analysis while opening the view.
The [first Groups browsing checkpoint](../.v-groups-browser-20261006-93bd/handoff.json) records all
7,259 offline tests passing with coverage after a final correct-source rebuild, 1,012 matching code
inputs and all 35 required new/adapted checks detecting rebuilt defects across 29 mutations with
passing restored controls.
Judgement format 59 saves captured group metadata and distinct text references from `member` during
the existing object pass; Evidence/Derivation formats, the 19-rule catalogue and prior analysis
semantics are unchanged.
The WPF view keeps actual domain identity, separate cycle outcomes, bounded pages and explicit
unavailable nested totals, supports double-click/Enter and direct-member navigation, and preserves
filters, selected row, page and scroll position when returning.
Filters remain visible during a refused read so their Clear action is usable, and whole-forest
browsing disables Base/One level rather than showing a scope it does not apply.
Earlier captured runs need judging with this build to populate the new inventory; no recapture is
required; that first checkpoint left saved structural totals for the separate pass below, with
physical-display/lab/production acceptance still outstanding.

**Owner-approved nested-total counting meaning, 2026-10-06.**
"Known total" counts distinct captured member objects reached directly or through nested groups,
including the nested groups themselves; count each object once and exclude the starting group
even when circular membership leads back to it.
A group containing Alice and another group containing Alice and Bob therefore has a known total
of three: Alice, Bob and the nested group.
Missing references remain separately reported limitations, not evidence of complete membership.
The owner subsequently approved beginning the proposed bounded implementation: follow captured
`member` links, matching the existing Direct count, and keep primary-group relationships separate.
Save totals during analysis and read them without calculation during browsing; retain "Known total"
and show "Incomplete membership evidence" beside affected results, with separate reference counts.
This does not authorize live access, measurement campaigns, budget changes, packaging, commit or push.
The [saved-total checkpoint](../.v-nested-totals-20261006-71af/handoff.json) records 498 passing
affected-area offline tests with coverage after a final correct-source rebuild, 1,015 matching
code/configuration inputs and all 38 required new/adapted checks detecting rebuilt defects across 18 useful
mutations with passing restored controls; failed and interrupted attempts remain retained.
Judgement format 60 now saves these totals and their limitations for Groups browsing.
Evidence and Derivation remain unchanged: current derivation-16 inputs can be reused for judging,
while derivation-15 results still need rederiving from the same sealed evidence, not recapture.
Physical-display, lab/production and forest-scale runtime acceptance remain outstanding; rendered
small/large-window checks are not physical-monitor acceptance, and no package was replaced.

**Owner-approved SEC-052 scope and wording, 2026-10-06.**
Report one fixed Medium finding per recorded set of groups joined by circular membership, including
a group directly containing itself; overlapping loops remain one finding with all involved groups
and source-backed direct membership evidence.
Reuse the saved cycle product and correct its self-loop omission, keeping missing/partial derivation
and captured evidence explicit rather than claiming no loops.
Use the existing Rules and Findings views with title "Circular group membership" and explanation
"These groups form a circular membership relationship. Review the recorded links and the membership
or permissions that depend on them; this finding does not establish a route to Tier 0."
Guidance is "Remove unintended nesting links after reviewing their impact. A set containing
overlapping loops may require more than one link to be removed."
Do not claim infinite Windows recursion, measured token-size problems, automatic High severity or
proven remediation; validate normal GUI/CLI judging and saved readback offline with rebuilt mutations,
preserving existing work, packages and campaigns without live access, commit or push.

The [SEC-052 checkpoint](../.v-sec052-20261006-8e3c/handoff.json) records all 7,228 offline tests
passing with coverage after a final correct-source rebuild, 1,002 matching code inputs and all 50
new/adapted checks detecting rebuilt defects across 26 mutations with 26 passing restored controls.
The normal catalogue now has 19 rules; derivation format 16 retains self-loops, and judgement format
58 stores the finding plus references that make the same single finding visible from every involved
group under object/domain/container filters.
Earlier format-57 and historical layout hashes, prior feature sources and all failed attempts remain
retained; original `member`/`memberOf` witnesses, scoped BUILTIN identities, deterministic component
identity, incomplete outcomes and source-generation refusals are verified.
Existing derivation-format-15 results must be derived again from their sealed evidence before this
build can judge them; no recapture or migration is required or authorized.
P-125's implementation gap is closed, not Stage 7 acceptance: presenting the new saved distance,
summary and best-route products, plus representative lab/display/production verification, remain owed.
No live directory operation, production-data copying, timing campaign, package replacement, commit
or push was performed.

**Owner-requested Tier 0 results presentation preview, 2026-10-06.**
After the saved nested-total slice, the owner requested a fictional-data preview for the already
saved distances, best-supported routes and whole-run coverage summaries.
The [interactive preview](../.v-ui-tier0-preview-20261006-582c/tier0-preview.html) proposes their
grouping in Assets > Tier 0, keeping shortest distance separate from route grading, classification
separate from reachability, and missing capture evidence separate from unsupported analysis and
processing limits.
On 2026-10-07 the owner requested a revision showing how these results connect to the existing
Path to Tier 0 object tab and Findings.
The revised preview keeps whole-run counts on the Tier 0 overview, opens selected captured objects
in their existing Path to Tier 0 tab, and links findings and recommendations to that same viewer.
Uncaptured identities open a saved-limitation panel instead of fabricated object details; route
ranking neither changes severity nor hides other unexpected results, and the first preview is retained.
The owner approved this revised wording and flow for implementation on 2026-10-07, with the
intention of trying it in the laboratory to assess the interaction, and requested closing the mockups.
Implement the connected presentation without replacing existing assessed-result groups or changing
finding qualification; offline verification precedes lab acceptance, and the approval is not itself
physical-display or lab acceptance.
No live access, package replacement, commit or push is authorized by this implementation approval.
The [connected-presentation checkpoint](../.v-tier0-presentation-20261007-b683/handoff.json) records
684 passing affected-area tests with coverage after a final correct-source rebuild, 1,023 matching
code/configuration inputs and all 18 new/adapted checks detecting rebuilt defects across 17 variants
with restored controls.
Assets > Tier 0 reads bounded pages and saved whole-run summaries; the existing object path section
shows shortest and best-supported routes with separate qualifications above its retained assessed
results, and Findings links to the same object section.
Returning from an object's findings preserves the route choice but reads its saved results afresh
under the protected generation; returning to the overview retains its page and selection.
No Evidence, Derivation, Judgement or path-calculation format changed for this presentation, and
prior stored judgement-60 results can be browsed without analysis replay.
Mockup serving was stopped; lab/physical-display/production acceptance and separately authorized
packaging remain outstanding, and the preview files and failed verification attempts are preserved.

**Owner-approved saved best-supported-route slice, 2026-10-06.**
Save a separate best-supported route and its source-backed grade, comparing complete evaluated
candidates before shortest-route selection discards alternatives.
Apply the accepted certainty/feasibility/conditions/confidence/length/stable-signature ordering,
using concrete requester and operation proofs rather than generic permission labels; unresolved
questions without complete supported steps are not invented possible paths.
Keep shortest supported distance, findings, SEC-071 severity, expected administration and screen
ordering unchanged, with exact generation-bound selected-only readback and explicit grading limits.
Verify offline with isolated rebuilt mutations, preserving current work and campaigns; no new
screens, live access, production data, timing campaign, budget change, package replacement, commit
or push is authorized.

The [best-supported-route checkpoint](../.v-best-route-20261006-4d7a/handoff.json) records a final
correct-source rebuild, 1,116 passing affected-area tests, 998 matching code inputs and all 34
new/adapted checks detecting rebuilt defects across 15 mutations with 15 passing restored controls.
Judgement format 56/path version 12 save the result separately; shortest-distance logic, requester
selection version 5, original permission/operation proofs, findings, page order, Evidence/Derivation
formats and historical layout hashes are unchanged.
The producer grades the currently complete supported proofs, not invented possible routes or
exhaustive alternatives; their definite/high grade concerns supported proof semantics rather than
live access or complete forest coverage, and both obtainable-membership permission kinds remain
conditional with distinct membership-outcome and enabled-authorization assumptions.
Missing grading evidence is counted with typed limitations, and stable signatures exclude saved
generation identifiers; a three-step existing-membership route outranks a two-step conditional route
without changing its saved shortest supported distance of two.
The selected saved result remains internal until a separately approved presentation change, with
SEC-052 and new lab/display/production acceptance outstanding and no storage-size or runtime claim.

**Owner-approved saved distance and whole-run coverage slice, 2026-10-06.**
Save each object's supported distance separately from whether the overall minimum is established,
and save whole-run classification/reachability/coverage totals during judging rather than deriving
them from displayed pages.
Keep classified Tier 0 objects separate from other supported reachers, preserve unresolved and
unassessed work, bind passive selected readback to the exact generation, and verify with synthetic
offline tests and isolated rebuilt mutations.
This slice adds no screens and does not change route ordering: certainty-first best-route selection
follows separately under the existing accepted rules.
Preserve all current work, packages and verification campaigns; no live access, production data,
new timing campaign, budget change, commit or push is authorized.

The [saved-distance checkpoint](../.v-distance-summary-20261006-2f8a/handoff.json) records a final
correct-source rebuild, 1,083 passing affected-area tests, 993 matching code inputs and all 28
new/adapted checks detecting rebuilt defects across 13 useful mutations with 15 passing restored
controls; the two earlier blocked/surviving mutation attempts and failed fixture attempts remain.
Judgement format 55 and path version 11 persist the extension; requester selection, Evidence and
Derivation formats, the 18-rule catalogue and earlier layout hashes are unchanged.
The saved total covers recorded analysis identities, including declared but uncaptured roots, not
captured inventory; those roots remain unresolved, classifications are not expanded to other
reachers, and distinct checked subjects are not counted as questions or routes.
Selected-object inspection remains internal until a separately approved screen consumes it, and
saved readback neither loads other objects' proofs nor replays analysis.
Best-route ordering remains next, followed by SEC-052; no new lab/display/production acceptance,
performance claim or package publication is established by this offline checkpoint.

**Owner-confirmed return to Stage 7 after a lab DNS refusal, 2026-10-06.**
After reporting that New audit returned to the domain screen when Next was pressed, the owner
identified a familiar DNS issue in the Azure-hosted lab and will correct it and retest.
This is the owner's diagnosis, not independently verified recovery; continue Stage 7 rather than
changing capture/preflight behavior or treating the symptom as a confirmed regression.
The owner noted that the Details warning was easy to overlook and suggested stronger attention
when an issue occurs; record that usability concern separately, with concrete wording/layout
approval still required before implementation.

**Owner-approved same-forest continuation after one membership outcome, 2026-10-06.**
Keep the first own-account membership assessment in its existing same-domain global-security-group
boundary, with Self-Membership and Write members separate, then extend its continuation through
supported captured same-forest group nesting to Modify permissions on a fixed Tier 0 domain target.
Preserve pre-change authorization, existing and newly applicable ordered denies, every original
permission and direct membership witness, resource-domain context and exact saved-generation binding.
Reuse the existing domain-qualified labels and "Allowed under the saved membership assumption; not
proof of current access or a completed Add" wording, without new panels or regrouping.
Validate automatic GUI/CLI selection and passive readback with synthetic offline tests and isolated
rebuilt mutations; wider initial permissions, non-domain resource contexts, SID-history/primary-group
expansion, multiple hypothetical changes and takeover simulation are not included.
No live AD, production-data use, new timing campaign, changed production budget, package replacement,
commit or push is authorized, and existing work and verification campaigns must remain intact.

The [validated continuation checkpoint](../.v-forest-continuation-20261006-6b2d/handoff.json) records
1,073 passing affected-area tests and all 39 new/adapted continuation cases detecting rebuilt defects
across 13 mutations with 13 passing restored controls.
A final correct-source rebuild after three XML comment clarifications passed all 39 continuation
cases and matched 990 code inputs; the earlier tree correction and all historical layout hashes
were preserved.
Judgement format 54, path version 10 and selection version 5 bind the extension without changing
Evidence/Derivation formats or the 18-rule catalogue.
The final checks corrected an obtained-group SID-history boundary to explicit unknown rather than
excluding a potentially applicable deny; this is not SID-history authorization support.
Initial membership permissions remain at their preceding boundary; saved distance/best-route/whole-run
summaries and SEC-052 remain subsequent Stage 7 work, with new lab, display and production acceptance
still outstanding and no customer-scale cost or timing claim.

**Owner-approved generation-bound directory-tree reuse, 2026-10-06.**
Entering Assets again for the same still-current protected run may rebuild the unchanged screen from
the completed tree already read in that lifetime instead of rerunning the whole-capture tree query.
The screen still enters at Objects, the first root and page one; a changed run, reopened lifetime,
invalid generation, capture, refusal or cancellation forces a full read.
This approval does not include SQL or index changes, integrity-policy changes, new measurements or
tooling, production-data use, UI wording/layout changes, the separate lab-launch investigation,
commit or push; return to Stage 7 after this bounded correction and offline validation.

**Owner-authorized footer-test correction commit and push, 2026-10-06.**
After all 7,077 offline tests passed with coverage, the owner authorized committing and pushing
the CI footer viewport fixture correction and its governing checkpoint.
Production UI is unchanged; integration still requires passing exact-head CI, and this authorization
does not extend to performance measurement or optimization.

**Owner-approved Gallery CI correction, 2026-10-06.**
The owner approved fixing the UI Gallery tool after exact-head CI failed to compile its shared
Shell themes, before any tests ran.
Keep the correction to the missing shared-source dependencies and isolated validation of the tool
and full solution, without removing projects from CI or changing application wording/layout.
The owner subsequently authorized committing and pushing this correction on 2026-10-06; passing
exact-head CI remains required before integration, and performance measurement or optimization
remains outside this approval.

**Owner-confirmed return to core work after a Rules comparison mockup, 2026-10-05.**
After the remaining-work review, the owner agreed to return to opening-performance and Stage 7
completion work, but first requested a Rules mockup with a selectable list on the left and the
selected rule's explanation on the right, instead of expanding cards down the page.
The comparison preview keeps Rules at top level without a directory tree, with independently
scrollable list/details, an adjustable divider and unchanged separation of severity, saved outcome
and guidance.
This request authorizes a mockup only, not replacement of the implemented WPF Rules layout or new
measurement/optimization code; other tree and pop-out decisions remain deferred.
The owner subsequently approved replacing expanded cards with the side-by-side Rules list/detail
view, then committing and pushing the accumulated UI work in this session.
Address the outstanding baseline CI/merge issue last before the Stage 7 continuation handoff;
merge only after the relevant exact-head checks pass, without treating a queued run as success.
Keep this approval separate from performance optimization, live AD access or pop-out implementation,
and preserve current packages and all earlier evidence/verification artifacts.
The full-suite run exposed an older control-edge layout host that did not load the embedded
object-section navigation, followed by genuine short-window space failures once it did.
The owner explicitly approved a bounded correction before committing: scroll the object
header/navigation within a compact area and keep permission tables and proof reachable below it,
without changing any results.
Retain the failed full-suite attempt; long qualification text must be scrollable end to end rather
than falsely required to fit in a single viewport.
The [list/detail and compact-object checkpoint](../.v-ui-rules-split-20261006-c48a/handoff.json)
records 95 passing final rebuilt checks and rebuilt negative witnesses for all ten required
split/layout cases; the earlier failed 7,074-case run remains retained.
The [final CI correction checkpoint](../.v-ci-progress-20261006-a47b/handoff.json) passes all
7,074 offline tests with coverage after the existing P-261 progress fixture was corrected to
observe queued messages while judging remains active, without changing the production late-report
guard; the adapted test detects a rebuilt missing-counter defect and passes restored controls.
The accumulated UI checkpoint is committed as `b3f18e0` on **ui-navigation**.
Use a superseding combined baseline/UI pull request rather than silently broadening #3's original
scope, preserving its failed-run history and requiring passing exact-head CI before merging.

**Rules-tab preview requested, 2026-10-05.**
The owner selected Rules for a design mockup, specifically asking for better formatting and a
cleaner interface for the expanded "What this rule looks for" text.
The proposed preview retains per-rule expansion but separates Looks for, Evidence used and
Does not establish/exclusions into readable labelled text and bullets, with a separate saved-run
outcome strip and severity/category labels.
Use current rule guidance as the source, preserve every qualification and whole-run scope, and
keep no findings, incomplete, failed and not-run outcomes distinct; fictional preview counts are
not measurements or a change to any security rule.
This request authorizes a mockup only, not application edits, new rule claims or pop-out windows;
the opening-performance investigation remains outstanding.
The owner approved the proposed Rules presentation, but raised its navigation placement before
implementation: Rules is a whole-run overview, not tied to the selected asset, and may belong beside
Home, Dashboard and Assets rather than inside Assets.
He is deferring the broader decision about directory-tree presence across other views until using
his external monitor; do not remove their trees as part of this discussion.
Recommend a top-level Rules page without the tree, bound to the same opened run, and settle that
specific navigation change before implementation rather than silently moving other views.
The owner explicitly approved Home | Dashboard | Rules | Assets | Settings, removing the Rules
subtab from Assets and its tree while keeping all other Assets views unchanged.
Rules must identify the same selected run, load only its saved executions through the protected
reader, and keep refusal/loading/not-run states distinct without introducing browsing-time analysis.
The implemented description layout uses authored guidance paragraphs for Looks for and Scope and
limitations, and the rule's declared captured/derived inputs for Evidence used, preserving the
canonical guidance rather than maintaining a second prose copy or guessing sentence boundaries.
The [standalone Rules checkpoint](../.v-ui-rules-20261005-b61e/handoff.json) records 767 passing
combined checks and 106 passing focused checks after the post-render correct-source rebuild, with
all 55 new/adapted cases detecting 19 rebuilt assertion defects and passing restored controls.
The old Assets rule-reading branch was removed rather than retained as a parallel implementation.
All 18 rule descriptions have authored scope paragraphs; 17 retain their text unchanged apart from
whitespace, and SEC-071 gains a report-condition introduction while retaining its existing qualification.
The real WPF render was checked after the Fluent expansion animation, with copyable guidance,
declared inputs and Microsoft reference addresses; rule logic, outcomes and saved formats are unchanged.
Owner visual and physical-display acceptance remain outstanding, as do slow opening and the earlier
unrelated regression/merge blockers, with no package replacement, commit or push.

**Delegations design preview requested, 2026-10-05.**
While testing the Home build, the owner requested a Delegations-tab mockup using the current visual
direction.
Prepare a fictional-data preview with a compact two-step principal/permission search, a readable
original-entry table, and a selected-entry panel separating recorded scope from membership attribution.
Keep direct/group-held and inherited-entry choices, domain disambiguation, visible limitations and
the recorded-permissions-not-effective-access boundary; preview selection and filter controls do
not authorize application changes or any new authorization/path analysis.
This additional mockup does not resolve the reported slow opening or authorize changes to integrity checks.
The owner approved implementing this Delegations preview within the existing tab, acknowledging
its information density.
He will consider whether some application views belong in pop-out windows when using his external
monitor; no pop-out windows or new window-management behaviour are approved in this slice.
The [Delegations presentation checkpoint](../.v-ui-delegations-20261005-a92d/handoff.json) records
721 passing combined checks after a final correct-source rebuild, with all seven new/adapted
cases detecting seven rebuilt defects and passing restored controls.
The in-tab layout separates search, original-entry results and selected membership/permission
evidence, retaining full supporting links rather than replacing them with an incomplete route
diagram; controls and details scroll on smaller windows while results retain usable height.
Existing whole-capture coverage remains in the shared Assets footer, and lookup, counting,
generation binding, cancellation and saved formats remain unchanged.
Owner visual and physical-display acceptance and earlier unrelated blockers remain outstanding,
with no package replacement, commit or push.

**Owner feedback and next work — Home preview and slow opening, 2026-10-05.**
The owner reports that Dashboard looks good, and selected Home as the last immediate UI area,
requesting a mockup with a short explanation of what SecureAD is and room for design suggestions.
This is positive Dashboard feedback, not blanket physical-display acceptance or clearance of the
existing regression/merge blockers.
He also reports very slow opening, attributes it to hash calculations and suspects costs elsewhere,
and asked whether to finish the UI redesign before investigating.
The owner clarified on 2026-10-06 that this report means launching the application in the lab,
not opening a selected saved run.
Focus the next bounded investigation on launch through usable Home, including its initial library
listing; saved-run navigation logs do not by themselves measure that interval.
Recommend the Home mockup and one explicitly approved bounded Home implementation, then make
startup/selected-run opening and repeated verification the next engineering priority; do not turn
this into further general UI expansion.
Distinguish startup, metadata-only library listing, selected-run verification, reopening and
subsequent browsing: Home listing must not hash evidence under the existing accepted decision,
and verified results are already shared for the protected open-run lifetime.
The present report has no new timing/build provenance, and earlier retained evidence includes a
file-open delay rather than hash CPU time; do not assert one confirmed cause for the current delay.
No integrity-policy change, optimization, live access or new measurement tooling is authorized by
the preview request.
The standalone fictional Home preview proposes "Capture once. Investigate offline." with a short
product explanation, a compact library-location strip, separate Capture/Analysis columns, a
prominent Open run action and left-aligned name/notes fields in the selected-run panel.
It demonstrates completed, unassessed and interrupted runs, keeping folder-date qualification and
baseline grouping, with location and infrequent run actions behind disclosures.
The owner approved implementing this Home preview.
Running-analysis status/Stop and action failures must remain directly accessible rather than being
hidden with the infrequent actions or when another run is selected.
Preserve metadata-only listing, scope/baseline grouping, explicit confirmation and command gating;
the slow-opening investigation remains separate, with no integrity or hashing changes in this UI slice.
The [Home implementation checkpoint](../.v-ui-home-20261005-f82b/handoff.json) records 711 passing
combined Home/Dashboard/Assets/library checks after a final correct-source rebuild and all nine new
cases detecting rebuilt defects with restored controls.
The actual WPF view was rendered with fictional runs; scope headings are explicitly legible,
unsealed runs have Open disabled while the underlying refusal remains intact, and running analysis
status/Stop are independent of selected-run disclosures.
The initial analysis-banner mutation exposed an assertion swallowed inside a simulated callback;
the corrected check observes state there and asserts afterwards, and both attempts are retained.
Owner visual and physical-display acceptance remain outstanding, with the earlier regression/merge
blockers unchanged and no commit, push or package replacement.

**Owner-selected next UI work — Dashboard redesign, 2026-10-05.**
The owner wants further Assets refinements but is deferring that visual review until his external
monitor is available because the 13-inch laptop is too small for it.
He selected Dashboard next and requested a drastic overhaul, supplying its current inventory screen.
Carry the approved coloured-surface/card direction into a concrete Dashboard preview before WPF
implementation; retain the accepted coverage-first, per-domain counting and exact Group Policy
shortfall commitments.
The remaining Assets and physical display checks stay outstanding, not accepted or prerequisites
to proceeding with Dashboard design.
The owner approved a Dashboard mockup first, preserving its coverage-and-inventory purpose rather
than adding security findings to this slice.
The standalone fictional preview proposes four inventory cards, a compact per-domain table,
expandable scope/exclusions and separate Group Policy/membership coverage panels, with scenarios
for all domains read, a deliberately excluded domain and a domain with no writable controller.
The owner explicitly approved implementing that preview in WPF: coverage-first header, expandable
scope, distinct inventory cards, domain table and separate Group Policy/membership coverage panels.
Retain zero-policy, missing/failed derivation, unread/excluded domain and confidential-attribute
qualifications; no risk score, finding totals, changed counting semantics or new evidence reads are
authorized by this redesign.
The [Dashboard implementation checkpoint](../.v-ui-dashboard-20261005-e19a/handoff.json) records
610 passing combined Dashboard/Assets checks after a final correct-source rebuild, with all 21 new
cases detecting ten rebuilt assertion defects and passing restored controls.
The real WPF presentation was rendered with fictional complete and incomplete captures; the domain
table preserves uncounted-domain explanations, the membership panel distinguishes known zero from
missing/failed derivation, and a zero-policy capture has no misleading completion bar.
Owner visual and physical-display acceptance remain outstanding; this checkpoint does not clear
the older full-suite timeout or baseline merge blocker, or authorize commit, push or package replacement.

**Owner icon feedback and redesign planning, 2026-10-05.**
The owner reports that the icons seem to work and supplied a screenshot, but wants the directory
navigation area a little wider.
This is positive feedback on the icon presentation, not blanket acceptance of all physical display
checks or clearance of the existing regression/merge blockers.
The recommendation is a modestly wider default tree pane with a draggable divider, then one shared
visual foundation demonstrated on Assets and object details before page-by-page refinement.
The proposed width/resizing behavior and concrete visual treatment still require presentation
approval; no broader redesign is authorized merely by discussing the implementation sequence.
The owner further emphasized a fresh appearance, easy reading and navigation, and strong preference
for adaptation to monitor size.
Treat responsive use of available space and per-monitor scaling as design requirements: maintain
readable text, adapt attribute columns and control wrapping, and keep long values, selected context
and capture qualifications accessible rather than merely enlarging a fixed layout.
These requirements are not acceptance of unperformed physical display checks or approval of a
specific breakpoint, replacement screen or theme.
The owner approved preparing the same Assets/object-details proposal at laptop and external-monitor
sizes before implementation.
The standalone synthetic preview demonstrates a 360-pixel adjustable tree, stronger panel and
attribute contrast, and two/three-column attributes while retaining the tree beside object details.
Its HTML is only a visual review aid, not a change from WPF; the concrete presentation still awaits
owner approval and does not clear the existing verification or merge blockers.
The owner liked the initial direction but rejected its still predominantly white content area and
insufficient distinction between attribute titles and values, then suggested cards.
He approved revising the mockup with blue-grey surroundings, tinted section headings, smaller
attribute labels and larger dark values; show compact cards and full-width treatment for long values.
The owner subsequently requested titles in the form "Account Name (sAMAccountName)" and a mockup
first: keep the technical name inline in parentheses, rather than deliberately placing it on a
separate line, with natural wrapping when space requires it.
After viewing that revision, the owner confirmed he prefers the inline parenthesized titles;
retain this presentation with the technical name visually quieter than the friendly title.
This approval is for the revised preview only, not implementation in WPF.
After seeing the card revision, the owner confirmed "now we are getting somewhere": retain this
colour/card/label-value direction for the next bounded proposal rather than returning to the
white-on-white treatment.
This is positive design feedback, not blanket implementation approval or physical display acceptance.
After approving the inline-title card mockup, the owner said "lets try it" and authorized the first
bounded Assets/object-details WPF implementation: coloured surfaces, responsive cards, inline LDAP
titles, a wider adjustable tree retained beside details, and the existing section choices above the
detail area.
Preserve every section, selected-only reads, copyable values, original/raw evidence and qualifications;
this is not approval for unrelated screen redesigns, package replacement, commit or push.
The [WPF pilot checkpoint](../.v-ui-cards-20261005-6e2a/handoff.json) records implementation on
ui-navigation with 474 passing bounded checks after a final correct-source rebuild and all 19
new/adapted cases detecting 15 rebuilt defects with passing restored controls.
Real WPF rendering and controls were checked offline with synthetic data; physical display and
owner lab acceptance remain outstanding, and this does not clear the previous full-suite or merge
blockers.
The pilot also corrects section selection being cleared during loaded-content replacement by
binding navigation to the existing section key; it does not broaden reads, change persisted formats
or require a new capture or judgement.
The owner tried the pilot and described it as a good starting point, but identified the lower-tree
scope area as differing from the approved mockup: the implementation still has vertically stacked
radio buttons under "Level" and a prominent directory path rather than the compact horizontal scope
control and quieter path.
Record this as a remaining presentation mismatch, not blanket acceptance of the UI or display checks.
The owner approved correcting only this lower-tree area to the mockup: "Browsing Scope" above
horizontal Base / One level / Subtree segments with a blue selected treatment, and a smaller,
regular-weight directory path underneath.
Keep scope semantics, initial Subtree, deliberate selection and whole-capture search disabling
unchanged, and verify that all three options fit at the divider's minimum width.
The [scope-presentation checkpoint](../.v-ui-scope-20261005-4d91/handoff.json) records 479 passing
combined checks after the final correct-source rebuild, including actual WPF control checks at
270/360-pixel navigation widths and 1x/1.5x layout scale.
All five new cases detected six rebuilt assertion defects with restored controls; the initial
symmetric-padding variant that survived is retained separately rather than counted as a negative
witness.
This correction remains uncommitted, does not change scope semantics or require rejudging, and still
needs the owner's visual trial rather than treating simulated scale checks as physical display acceptance.
The owner next requested moving Capture coverage out of the strip above the tree and into the
bottom-right area under the grid, to the far right of the object paging controls, reclaiming the
space above the tree and results.
Keep capture-wide coverage accessible on every Assets view and while reading an object, retain a
visible incomplete-capture indicator, and show the existing details above the footer with scrolling;
allow the footer to wrap on narrow windows rather than clipping warnings or paging controls.
The [coverage-footer checkpoint](../.v-ui-coverage-footer-20261005-9b62/handoff.json) records 483
passing combined checks after the final correct-source rebuild, with all four new cases detecting
six rebuilt defects and passing restored controls.
Synthetic real-WPF checks cover reclaimed top space, right-aligned coverage beside the object
pager, working page commands, narrow-window wrapping, scrollable details above the footer and
continued coverage access across Assets views and object details.
No coverage calculation or saved format changed, and all assistant builds remained isolated;
concurrent publish-output changes were recorded and left as found rather than restored.
Owner visual acceptance and the earlier unrelated verification/merge blockers remain outstanding.
The owner reports that the relocated coverage control is better, then identified empty OS cards
on a user as misleading: "Not in this bundle" suggests missing information where the normal user
presentation should not offer computer-oriented fields.
The owner approved the bounded Account-card correction: computer OS fields should not be empty
cards on ordinary user accounts, relevant missing fields stay visible, and "No captured value"
replaces "Not in this bundle" with the explanation "The attribute may be unset or unavailable to
the capture account"; explicit "Not read" remains distinct.
Retain the existing distinction between class-based presentation and missing evidence: absence
alone does not establish that a field is inapplicable, unset or unreadable, and captured values
outside a class's normal sections must remain accessible.
Implementation inspection found that Other captured values is still a placeholder, despite the
catalogue describing it as the destination for unclaimed values.
Do not remove populated fields from their current presentation until a working readback destination
exists.
The owner approved completing Other captured values as part of this correction, with "No additional
captured values" when there are none and an explicit "Not read" state when evidence was not read.
When asked whether that section should also expose the catalogue's older exclusions (managedBy,
dNSHostName, dSHeuristics and objectCategory), he requested a mockup with made-up information first.
The owner approved the fictional-data preview, including exposing those formerly excluded populated
attributes under their LDAP names in Other captured values, without treating managedBy as the
security owner or interpreting raw dSHeuristics settings as a security conclusion.
Implement the approved Account-card correction and that read-only section together; the
distinguished name remains in the header rather than being repeated as a card.
The [class-aware attribute checkpoint](../.v-ui-attribute-cards-20261005-c73a/handoff.json) records
544 passing combined checks after the final correct-source rebuild, including all 34 new/adapted
cases detecting rebuilt assertion defects with restored controls.
Normal Account cards now reserve OS fields for computers; Other captured values displays populated
unclaimed attributes for the captured class, including the formerly excluded values, while retaining
stored order and the distinction between empty, unread and refused results.
Reads remain selected-only and bound to the protected object lifetime; no capture, judgement or
saved-format change is required, and owner visual acceptance and earlier unrelated blockers remain open.
The owner next raised the shared Overview cards, specifically a computer showing an empty UPN
card, as the next class-aware presentation item.
Apply the same distinction in the proposal: normal presentation is chosen by captured object type,
not by absence alone, and an unusual populated UPN must remain accessible in Other captured values.
This discussion is not a blanket instruction to hide every empty attribute or a claim that computers
cannot carry a UPN.
The owner requested a comprehensive Microsoft-documentation-backed pass over supported object types
and captured attributes rather than successive one-card corrections.
Microsoft's [Computer class](https://learn.microsoft.com/en-us/windows/win32/adschema/c-computer)
explicitly lists userPrincipalName as an optional inherited User attribute, and
[class definitions](https://learn.microsoft.com/en-us/windows/win32/ad/characteristics-of-object-classes)
include superclass and auxiliary-class attributes: schema allowance is not proof of a populated value.
Microsoft also documents that [read permissions can silently omit properties](https://learn.microsoft.com/en-us/windows/win32/ad/access-control-and-read-operations).
Do not treat the capture-justification catalogue as a schema applicability authority or published
standard definitions as proof of every customer's extended schema.
The current schema capture does not include complete class attribute/inheritance lists, so this UI
work must not claim to have established forest-specific applicability from the saved data.
The owner approved a single display policy across all existing attribute-card sections: populated
captured values by default, with "Show missing attributes" available to reveal omitted cards.
This supersedes the earlier default of keeping relevant missing cards visible; failed/unperformed
reads, capture gaps and section-level analysis qualifications remain visible independently.
The toggle filters already-loaded presentation only, not capture, classification, counts or saved
results; it starts off when a section is freshly loaded and is not a persisted preference.
The [shared card-policy checkpoint](../.v-ui-populated-cards-20261005-d81c/handoff.json) records
556 passing combined checks after the final correct-source rebuild and all 14 new/adapted cases
detecting rebuilt defects with passing restored controls.
Overview, Account, the shared attribute sections, linked policies and Other captured values now use
the same presentation filter; actual recorded empty strings and zero-length byte values are retained,
while empty optional cards can be revealed without another read.
This is a Microsoft-grounded presence/absence display policy, not a completed forest-schema
applicability engine or permission inference; original capture meaning and other section warnings
remain unchanged.

**Owner-selected next UI slice — directory-tree icons, 2026-10-05.**
After the navigation lab candidate and its bounded verification handoff, the owner selected icons
as the next UI item to consider.
Recommend a tree-only pass using embedded Microsoft Fluent vector assets, distinguishing domains,
OUs, ordinary containers, Configuration and Schema where captured metadata establishes the type,
and retaining an explicit generic/uncaptured treatment otherwise.
The owner approved that tree-only icon set: small dark-blue/slate icons immediately before the
labels, with domain/network, hierarchy-folder OU, folder container, settings Configuration and
layered Schema shapes, plus a generic treatment retaining the existing uncaptured indication.
This does not reopen the unrelated test-repair cycle, authorize a wider theme change, or clear the
existing merge/final-regression blockers.

**Tree-icon checkpoint — focused verification passed, 2026-10-05.**
The approved tree-only icons are implemented on ui-navigation using five Microsoft Fluent
20-pixel vector sources, rendered at 16 pixels with the existing dark-blue/slate brushes; the OU
combines the folder and organization symbols and the existing uncaptured wording remains visible.
Object class and partition kind are carried from the captured tables without a persisted-format
change, and neither names nor missing evidence are used to invent an object type.
The Microsoft source revision and MIT license are retained and the license is embedded in the app;
no icon font, new package, capture, rejudging, publication, commit or push was introduced.
The [focused checkpoint](../.v-ui-tree-icons-20261005-4af0/handoff.json) records 268 passing relevant
checks after the restored-source rebuild and all 24 new/adapted cases detecting ten rebuilt defects
with passing restored controls.
Existing navigation work was preserved; this does not clear the unrelated full-suite timeout or
the GitHub Actions outage/merge blocker, and owner lab/display acceptance remains outstanding.

**Navigation implementation checkpoint — lab candidate, final verification blocked, 2026-10-05.**
The approved first navigation slice is implemented and uncommitted on **ui-navigation** in the
existing Stage 7 checkout: whole-capture object search above the tree, default Subtree browsing,
search result domain/location, and compact expandable capture coverage.
All 33 new/adapted navigation cases have rebuilt negative witnesses, and actual navigation and
coverage controls passed the focused layout checks; the isolated tree-resource test's missing WPF
startup was corrected without changing the application's startup.
The full offline run completed **6,932 passed / one failed / 6,933 total**: the existing
`NewAuditViewModelTests.HowFarTheJudgingHasGotIsShown` timed out, with cause not established.
The owner raised the cost and length of the session, so no further open-ended test-repair cycle is
authorized by this checkpoint; retain the failed runs and report the blocker rather than claiming
the navigation build is fully verified.
The owner was told the branch is available for a separate-folder lab trial, not production adoption;
subsequent preservation differences were confined to Release/publish outputs, consistent with that
build activity, while no unexpected source changes or recorded lab-evidence changes were detected.
The audit/delegation baseline was committed and pushed in [#3](https://github.com/TYMAR-Tech/SecureAD.Next/pull/3),
but is **not merged**: the latest exact-head CI run for
`be596f04f9cfbcec4ff444a81a4aa924ff7195c5` was cancelled, not passed.
GitHub's subsequently checked annotation states **The job was not acquired by Runner of type
hosted even after multiple attempts**: this last run never obtained a runner, has no job steps/log,
and is not evidence of a person cancelling it or another test failure.
The [blocked handoff](../.v-ui-navigation-20261005-e4b6/handoff-blocked.json) retains the branch,
test, mutation, preservation and CI references; the broader theme/icon overhaul remains unstarted.

**Owner-selected first UI implementation and production delegation feedback, 2026-10-05.**
Do the navigation changes first: whole-capture object search above the tree, Subtree as the initial
browsing scope, and replacement of the large gap box with compact, accessible capture coverage.
The broader palette, typography and icon redesign follows rather than being bundled into this
first implementation.
The owner reports that the delegation build is working well in production and results are quick
to retrieve; this is positive usability feedback, not a new instrumented timing, a binary identity
record or acceptance of every membership/security case.
The owner explicitly approved a local checkpoint commit of the currently verified work on
**stage7-completion**, followed by creation of **ui-navigation** in the same existing
`C:\Users\jistrand\source\repos\SecureAD.Next-stage7` checkout.
The owner subsequently approved pushing that verified audit/delegation checkpoint, opening a pull
request into **main**, and merging it only after its build and test checks pass.
Create **ui-navigation** from the same saved baseline while those checks run, so no navigation edits
enter the audit/delegation pull request.
This does not authorize a new checkout/worktree, package replacement or automatic commit/push of
the subsequent UI changes; use the same existing checkout throughout.

**Owner-requested navigation changes, 2026-10-05.**
Add an object-search field above the directory navigation tree; the predecessor screenshot is a
placement reference only, not a request to copy its styling, layout or architecture.
The owner selected **Entire selected capture** as the search scope, not the currently selected
subtree and not merely the containers already visible in the tree.
Search results must make domain and location clear so similarly named objects can be distinguished.
Change the initial listing scope to **Subtree**, retaining Base and One level as deliberate alternatives.
Remove the large persistent **Not shown, and why** box beneath the tree so that navigation regains
the space; the owner permits general explanations in Help or a better on-screen presentation.
Separate general product-scope explanations from run-specific unread or incomplete evidence:
the latter must remain apparent on the relevant screen, with its details still accessible.
The recommended replacement is a compact **Capture coverage** control with a visible incomplete
state when this run has capture gaps, while Help explains general exclusions; its concrete design
and the remaining search interaction are still to be agreed before implementation.

**Owner-approved first navigation layout, 2026-10-05.**
Use **Search captured objects** above the tree with an explicit Search button and Enter submission,
not a whole-capture query on every keystroke.
Show global matches in the **Objects** area with name, type, domain and location; double-click opens
the selected object, and **Clear search** returns to tree browsing.
Start browsing at **Subtree** and retain the existing Base and One level alternatives.
Replace the persistent lower-tree gap card with compact **Capture coverage** above the content;
its accessible details separate general exclusions from actual run-specific unread/missing data,
and the latter remains visible as **Capture incomplete**.
This approved batch excludes a full Help page, theme overhaul and icons, which remain later UI work.

**Owner-stated UI redesign requirements, 2026-10-05.**
The owner confirmed UI work is next while he tests the latest nested-delegation changes in the lab,
and asked for design consideration during that test rather than changes to the tested package.
Keep the UI's packages first-party Microsoft and make the application as sleek
and modern as WPF permits, with clearly readable attributes and strong distinction between an
attribute's title and its value.
The directory navigation tree must have recognizable icons, comparable in usefulness to ADUC;
the icons need not be identical to ADUC's.
This adds concrete requirements to the white-on-white overhaul, not approval of a particular
replacement layout or palette; retain the accepted light-theme and truthful-state distinctions,
preserve LDAP names/raw values/capture qualifications, and obtain approval for the concrete design
before changing UI code.

**Owner-returned production judgement — published, 2026-10-05.**
The [retained production log](../.v-production-log-20261005-0708-c2a7/run.log), SHA-256
`7D1EB652BB9C3567B97945F8E210907E56FAAF1B11C41051EB6A6BE8E472B33B`, matches the previously
verified detailed-sealing lab package: executable `3404F82A5DA39EE33CD6DF1A0F84884BC8B8101CEF5CD08280BE3DFDB1348AE6`
and judging module `4a1dba56-cf2c-47be-b7c4-0aceb4e26b92`.
Judgement `6e5e694d-96c1-4565-8c2f-21996fb6a28e` used the same evidence seal and derivation generation
as the retained failed production attempt, with 940,067 objects, 267,550 descriptors and 141,693,937
permission-entry positions.
The attempt ran from 02:29:22 to 07:06:47 UTC, **4h 37m 25s to Published**, versus 15h 44m 7s to the
old failure; the observed elapsed reduction is 70.6%, not a controlled equal-work benchmark.
It completed 110,385 selected questions rather than 50,694: requester permissions increased from
7,150 to 66,841, while own-account membership and combined questions remained 28,790 and 14,754.
Those three answering phases together fell from 11h 1m 4.7s to 2m 7.6s, and proof writing completed
in 8m 53.8s instead of throwing an out-of-memory exception.
The result state is **CompletedDegraded**, with 11 rules Succeeded and seven Indeterminate, not an
all-clear or proof that every object received a definite answer; the log gives no per-object causes
for all of those qualifications.
The judgement file was 22,001,786,880 bytes, with sealing at 69.4 seconds and opening at 1.674 ms,
so the ten-second lab file-open pause was not observed here.
The largest recorded private-memory snapshot was 12.04 GiB, not a measured whole-process peak;
successful proof publication does not establish a generally small memory footprint.
The object pass still took 1h 55m 30s, control assessment 43m 23.7s and ownership assessment
41m 21.2s, while path preparation was 44m 42.2s; scope selection and control assessment were slower
than in the prior attempt, so the improvement is not uniform across phases.
The [source-bound review](../.v-production-log-20261005-0708-c2a7/review.json) retains exact comparisons
without summing repeated cumulative progress records.
Publication and production-scale judging improvement are now demonstrated, while completed-run
browsing, saved-answer equivalence and demo acceptance still need the owner's local checks; no
production database/export is requested, and this review authorizes no new optimization or live action.

**Owner-approved nested delegation presentation, 2026-10-05.**
Extend Assets -> Delegations with **Include group-held permissions**, on by default, and a
**Permission held by** result column distinguishing the selected principal's entries from a
containing group's entries.
Selecting a group-held entry must explain the **Membership chain**, including captured primary-group
membership and ordinary nesting, without multiplying an original permission occurrence by its
membership routes.
Missing membership evidence and uncertain group types must remain explicit, and distribution-group
links must not be presented as usable security-group routes.
Retain **Recorded permissions - not an effective access check**, preserve resource/domain scope,
and read the current evidence plus saved membership data without changing persisted formats or
requiring the production judgement to be repeated; unchecking the option retains direct-only lookup.
This is the next approved implementation, followed by a separately presented broader UI overhaul.

**Nested delegation checkpoint, offline verified, 2026-10-05.**
The approved default-on group-held lookup is implemented using the saved reverse membership index,
with primary-group links, cycle-safe containing-group traversal and retained alternative supporting
links; original permission occurrences are not multiplied by route count.
Holder GUID/SID/resource-domain identity and the exact evidence/derivation generation bind each
page, while missing nesting is refused rather than replaced by direct-only success.
The [retained checkpoint](../.v-delegation-nesting-20261005-7ac2/handoff.json) records 6,905 passing
offline tests and all 31 new/adapted cases detecting 25 rebuilt defects with restored controls;
the initial inlined-SQL query-plan check that survived its defect was corrected and the failed
attempt retained.
Verification includes a 2,000-link chain with unrelated nodes, primary/ordinary witnesses, multiple
routes, cycles, scoped built-in groups and real direct/group-mode WPF controls at both checked sizes;
these are correctness/work-shape checks, not production query-speed measurements or a nesting limit.
Current persisted formats, the owner's packages and screenshot, all original evidence and prior
verification artifacts remain unchanged, with no assistant publication, live AD access, commit or push.
Owner lab/demo acceptance and physical display checks remain open, and the broader visual redesign
is the next work to present for approval.

**Owner-approved delegation follow-up order, 2026-10-05.**
The owner reported that the matching-principal picker was hard to see against the otherwise white
screen and approved automatically selecting the sole match, with a **Matching principal** label.
Only a first page containing exactly one result with no continuation may select automatically;
multiple matches still require a deliberate choice of domain/SID.
Fix this selection step first, add nested-group delegation visibility next, and then address the
broader UI: the owner wants a substantial overhaul of the white-on-white presentation, not merely
an extra-click fix.
The nesting goal is approved as the next work, while its concrete bounded scope and presentation
must still be put to the owner before editing; the later visual overhaul likewise needs a concrete
presentation approval rather than speculative theme changes now.

**Principal-selection correction, offline verified, 2026-10-05.**
The picker now has its approved **Matching principal** label and automatically selects a sole
first-page match without cancelling the completing read or starting a delegation search unasked.
Ambiguous, empty, continuing and single-tail pages still require selection, and late results from a
cancelled or superseded search cannot supply the selected identity.
The [retained checkpoint](../.v-delegation-selection-20261005-19c3/handoff.json) records 1,459 passing
Shell/Architecture tests and all 12 new/adapted cases detecting seven rebuilt defects with restored
controls; the real small/large-window tests now reach Find delegations without choosing the sole
result for the operator.
The owner screenshot, current owner-built packages, original evidence and prior verification artifacts
were preserved, with no format, query-semantics, publication, live AD, commit or push change; nesting
and the broader visual overhaul are not delivered by this correction.

**Owner-approved direct-entry demo delegation lookup and parallel UI work, 2026-10-04.**
The owner confirmed production judging has started and asked to work on UI while that unchanged
build runs, with a demo request to find where a selected user or group has delegated permissions in
a long-lived forest, including password reset and creating/modifying users.
This is a request for a guided read-only lookup over captured evidence, consistent with the retained
[query-tool specification](specs/the-query-tool.md), not approval for live directory changes or an
arbitrary access/takeover claim.
The lookup must not be limited to current Tier-0 findings or scoped control-edge assessment, and
must distinguish recorded grants, inheritance/applicability, denies and incomplete capture from
effective requester authorization or completed paths.
The owner approved **Assets -> Delegations** for the first version: a name/SID principal picker
with domain disambiguation; All recorded permissions, Reset password, Create user objects and
Write user properties filters; recorded-on object/container, domain, permission, applies-to,
Allow/Deny and Explicit/Inherited results; explicit entries initially, with Include inherited entries;
and navigation to permission details.
Broader permissions containing the selected right must be included, and an inherited entry must
not invent its originating ancestor.
The screen must say **Recorded permissions - not an effective access check** and explicitly state
that only entries naming the selected principal are included; group-derived permissions are not.
Use read-only, bounded queries with capture coverage, no severity, SQL editor, export, live AD,
format change or requirement to recapture/rejudge the run now in progress.
The owner deferred nested-group lookup from this first slice, not because it is unwanted or
inherently unsafe, and requested it immediately afterwards: deep group nesting obscures delegation
in real environments.
That next extension must show the permission-holding group and membership route with resource/domain
scope and missing-evidence qualifications, not equate membership attribution with effective access;
its concrete presentation and implementation scope remain to be approved separately.

**Direct-entry delegation lookup checkpoint, offline verified, 2026-10-05.**
The approved screen is implemented as an AD-object evidence lookup, so it does not require a
completed judgement or change the current Evidence 8 / Derivation 15 / Judgement 53 formats.
Reverse indexes locate candidate descriptors only: results retain the original entries, duplicates,
order, raw shorthand, conditions, resource domain and capture qualifications, with evidence-bound
continuations and no result cap or inferred whole-search total.
Write-user-property entries with unresolved descendant-class applicability remain explicitly
qualified rather than being silently discarded or presented as confirmed user scope.
The [retained checkpoint](../.v-delegations-20261005-4c91/handoff.json) records 6,866 passing offline
tests and all 61 new/adapted checks detecting 38 rebuilt defects with restored controls, including
real WPF control/layout checks at 900x470 and 1300x700 logical view sizes.
The current production package, original evidence and prior verification artifacts were preserved;
no assistant publication, live AD access, commit or push occurred, and owner lab/demo acceptance,
physical laptop/external-monitor checks and the ongoing production judgement result remain outstanding.

**Owner-run production test and parallel read-only review, 2026-10-04.**
The owner will take the same build just tested in the lab to production and start a test, then supply
only the run log under the existing production-disclosure restriction.
The lab reference is the detailed-sealing package identified below; do not infer a production result
or exact workload before the new log arrives.
While that owner-run test proceeds, inspect current code read-only for further performance
opportunities through publication, separating confirmed repetition from measured runtime cost.
Preserve source, packages, original evidence and all prior artifacts; this does not authorize agent
production access, live AD actions, a new measurement campaign, further implementation, packaging,
commit or push.

**Owner-reported demo deadline and sealing frequency, 2026-10-04.**
The owner has a demo in two days and asked whether the measured file-open delay should take
priority over further judging-performance work.
Creating a seal happens once per newly completed Evidence, Derivation or Judgement file, not per
object, permission or requester question; closing/reopening a run separately verifies the required
files again, with those checks shared while the selected run remains open rather than repeated
per screen.
The current post-judging portable-summary path also opens and verifies the completed judgement,
so the end-of-run seal must not be described as the only file read or integrity check.
The observed ten-second file-open pause is not guaranteed to occur only once or scale with file size;
its cause and behaviour on the production machine remain unestablished.
The recommendation is to prioritize a completed, browseable demo candidate and production-scale
judging evidence over speculative sealing changes, escalating the file-open investigation if it
blocks completion or usable reopening; this is not owner approval for a production run, new
measurement campaign, further code changes, packaging, commit or push.

**Owner-run detailed-sealing checkpoint, 2026-10-04: the pause is in opening the judgement file.**
The [retained log](../.v-lab-log-20261004-51b9/run.log), SHA-256
`5A2D72B71166E6CABE89C16A2007DA3B5125D41E2C60B0B9E838E38A01C82231`, matches the exact
owner-published executable fingerprint
`3404F82A5DA39EE33CD6DF1A0F84884BC8B8101CEF5CD08280BE3DFDB1348AE6` and verified engine module
`4a1dba56-cf2c-47be-b7c4-0aceb4e26b92`; the publish reported during final verification contained
the checked diagnostic build.
All 18 rules and 459 selected questions completed for the same reported 8,441 objects, and the
judgement was published successfully without logged errors or cancellation.
Judgement sealing took 10,279.312 ms, with **10,042.115 ms inside the data-file open call** before
reading began; reading 48,369,664 bytes took 31.793 ms, hashing took 203.755 ms, data-file close
0.118 ms and seal-record writing 1.279 ms.
The 592 reads included EOF, and the longest read and hash calls were 1.176 and 2.472 ms; evidence
and derivation file opens in the same run were 1.024 and 2.477 ms.
This localizes the observed pause to opening the completed judgement database, not checksum
calculation, sustained reads, seal-record writing or the earlier permission checks.
The log does not identify the Windows/file-system component responsible; a local lab file-access
trace of the slow open is the next diagnostic, not disabling security software, changing the hash
algorithm or removing corruption checks on speculation.
Any such trace stays in the lab for local inspection, and this review performed no tracing, live AD
operation, code change, package replacement, commit or push.

**Owner-approved detailed sealing diagnostics, 2026-10-04.**
The owner approved adding useful performance detail to the run log after judgement sealing was
measured at 9.956 seconds, specifically to separate data-file opening/reading, hashing and seal-record
writing instead of guessing at the cause.
Record aggregate timings, bytes, read calls and completion/failure/cancellation for capture and
analysis sealing, without object-level exports, new live access or a timed measurement campaign.
Keep the checksum algorithm and bytes, read buffer, file-sharing/write behaviour, corruption checks,
generation binding, cancellation/publication boundaries and saved formats unchanged; the existing
seal-file write operation remains intact and its timing includes opening/writing/closing that small file.

**Detailed sealing diagnostic outcome, 2026-10-04: implemented and offline verified.**
Normal capture, derivation and judging now write one aggregate `file sealing` record identifying the
artifact and analysis generation, completed/failed/cancelled outcome and any interrupted operation.
Separate elapsed timings cover data-file open, reads, hash updates/finalization, data-file close,
seal serialization and the unchanged seal-record write; bytes read/hashed, read calls including EOF,
longest read/hash call, buffer size and unaccounted time are recorded without per-buffer log output.
The timings describe elapsed operations rather than CPU time and stop before the diagnostic log
write; seal-record writing still includes its original open/write/close operation.
The [validated checkpoint](../.v-seal-detail-20261004-f31e/handoff.json) records 6,807 passing offline
tests, all 22 new checks plus one strengthened diagnostic-isolation check detecting 19 useful rebuilt
defects with restored controls, and 944 matching build inputs in the now-71-path uncommitted tree.
Failed attempts are retained: the original log-isolation check missed a sealing-record retry after
post-pass logging had failed, and the first full run caught a timing-method ownership name and
null-default collaborators; the checks were strengthened and production corrected, not waived.
Checksum bytes, the 81,920-byte read buffer, file sharing/write operations, corruption verification,
saved formats and publication/cancellation boundaries are unchanged; historical evidence and all
earlier verification artifacts remain preserved.
The owner reported pressing Publish during final verification: nine ordinary Release/publish files
changed without source/evidence changes, and read-only inspection matched the replacement engines
and their published symbols to 273 final source documents rather than restoring over the owner's work.
Evidence 8, Derivation 15, Judgement 53, path calculation 9, requester selection 4 and all 18 rules
retain their versions, and all 39 recorded layouts remain unchanged.
This adds diagnosis rather than a sealing-speed fix: the subsequent owner log above isolates the
file-open step, while the responsible component and production acceptance remain unestablished.
No agent live access, new timed campaign, package replacement, commit or push was performed.

**Corruption protection, not deliberate-tampering or court proof — owner reaffirmed, 2026-10-04.**
The owner requires protection against data corruption but not proof against a person intentionally
editing captured files, and does not require court-use or forensic authenticity.
This reaffirms accepted [0020](decisions/0020-the-seal-detects-corruption-not-tampering.md) and
[0030](decisions/0030-the-product-produces-sealed-evidence-never-signed.md), rather than introducing
a new threat model: the adjacent checksum is a corruption control, not a signature or protection
against alteration followed by recomputing that checksum.
Keep corruption detection, coherent completed publication and exact evidence/derivation/judgement
binding distinct from malicious-tampering claims; this clarification does not authorize removing
those safeguards or changing the current on-open verification lifetime.
The detailed timings and subsequent owner log now isolate the file-open step; the responsible
component still needs identification before choosing a correction.

**Owner clarification of the performance goal, 2026-10-04.**
The predecessor's 4-6-hour whole-audit time is not the target for an audit that now captures additional
SYSVOL evidence; the owner explicitly expects that extra capture work to take time.
The requirement is demonstrable improvement in judging the large production forest, without reduced
coverage, weaker evidence or conflating capture time with analysis time.
No numeric judging ceiling, production retry or new measurement campaign was authorized by this
clarification.

**Owner-selected next work — whole-audit memory/performance, in a fresh session, 2026-10-04.**
After the production out-of-memory failure and the coverage-preserving efficiency review, the owner
said "i want this to be the next work but lets do it in a new session".
Make this the next priority ahead of further Stage 7 feature expansion, starting with one bounded
proof-storage memory correction before tackling shared prerequisite/source preparation and other
repeated work.
Keep every original occurrence, permission/membership witness, saved answer, exact generation binding
and explicit uncertainty; speed must not come from truncation, reduced coverage or weaker checks.
Carry forward the approved direction without another general efficiency-proposal session, while
raising any new product/public-contract decision concretely before implementation.
This does not authorize a new timed measurement campaign, production retry, original-bundle
rejudging, live AD work, package overwrite, new checkout/worktree, commit or push.

**Owner-approved versioned source-fingerprint reuse, 2026-10-04.**
Fingerprint shared source/schema/domain material and prepared target evidence once, then bind each
membership and requester-permission proof to those components without removing evidence, witnesses,
independent authorization or explicit uncertainty.
The owner explicitly approved Judgement format 53 for the changed source-fingerprint method:
source fingerprints intentionally change, while security answers and original evidence remain intact.
Older saved judgements are refused rather than migrated; using the new reader for them requires
rejudging, and historical results, hashes and verification artifacts must not be overwritten.
Verification remains isolated and offline, with exact-answer comparisons, independent component
binding checks, work counts and rebuilt defects/restored controls; no production run, timed campaign,
live access, package replacement, UI change, commit or push is authorized.

**Owner-run format-53 lab checkpoint, 2026-10-04: completed; publication pause localized to sealing.**
The [retained log](../.v-lab-log-20261004-23d0/run.log), SHA-256
`4DC2EDB7A2EEB46E0121BB03FD1ED80D0472174844470988C7C2607C55C51A12`, records all 18 rules
succeeding and all 459 selected questions completing for the same reported 8,441 objects,
381 descriptors and 11,189 entry positions, without logged errors or cancellation.
Engine module identity `b276c67c-5223-4188-bd03-836ae7e06cb0` matches the local Release engine and
its 106 compiler-recorded source checksums, with all 942 build inputs matching the format-53
checkpoint; executable SHA-256 is
`191EDA9442D763EB855B48F2CF629E994AB09CA65B47E5E365D69199D98F9A06`.
Requester checks took 604.4 ms versus 726.0, own-account checks 857.0 versus 1,016.7, and combined
checks 475.1 versus 567.0 in the preceding log, while proof writing increased from 1,422.3 to
1,990.2 ms and the object pass from 4,478 to 4,729 ms.
Publication completed in 10,048 ms, of which 9,956 ms was `seal-generation`; final proof validation,
index creation, database checkpointing and manifest selection were not the long step in this run.
Sealing includes opening/reading/hashing the judgement file and writing its seal record, which are
not separately timed, so the internal cause remains unknown rather than attributed to disk,
antivirus or hashing CPU without evidence.
Judging was approximately 29 seconds versus 18, so this is not an overall judging speedup claim;
the comparison is between owner-run captures with matching reported counts, not controlled
same-evidence performance or saved-answer equivalence verification.
No code, lab configuration, package or original evidence was changed by this review.

**Versioned source-fingerprint outcome, 2026-10-04: implemented and offline verified.**
Judgement 53 uses versioned component fingerprints for membership and requester source proofs:
shared schema/domain/context material is hashed once per preparation, target evidence once per batch,
and repeated obtained-membership assessments once within the requester producer.
Each question still binds its complete requester data, applicable membership witnesses and resource
context to the exact evidence, derivation and judgement generations; source hashes intentionally
change, while all security answers, original source fields, occurrence order and uncertainty remain.
No encoded whole-source cache is introduced; retained bookkeeping is digests and references within
the existing preparation lifetime, and aggregate generation-tagged hash counters expose work without
object-level data.
The [validated checkpoint](../.v-source-fp-20261004-e5d2/handoff.json) records 6,785 passing offline
tests in one final full regression, all 54 new cases plus 53 adapted checks detecting 22 rebuilt
defects with restored controls, and 942 matching build inputs in the now-63-path uncommitted tree.
Normal proof creation for 16 synthetic accounts and two groups produces 64 membership questions
with one shared and two target hashes, while 32 combined questions across two permission targets
hash their 16 distinct obtained-membership assessments once each.
A separate 50,694-call repeated-input check with nine synthetic domain labels keeps shared, target
and unchanged-requester preparation at one hash each; this is an algorithmic work-count check, not a
representative forest, production timing result or memory acceptance campaign.
Evidence 8, Derivation 15, path calculation 9, requester selection 4 and all 18 rules are unchanged,
and format 53 keeps the physical layout of 52 while preserving all 38 earlier layout hashes.
The new reader refuses older judgements rather than migrating them; original evidence, historical
results, prior lab-tested packages and all earlier verification attempts remain preserved.
The subsequent owner-run format-53 completion is recorded above; production judging benefit,
detailed saved-output/display and wider acceptance remain outstanding.
No agent live access, original-bundle rejudging, production retry, timed campaign, package
replacement, UI change, commit or push was performed.
Repeated permission-entry interpretation across descriptors remains the next recorded performance
opportunity, and demonstrable production judging improvement remains unaccepted.

Work stays in the existing `C:\Users\jistrand\source\repos\SecureAD.Next-stage7`
checkout on `stage7-completion`; this correction started at HEAD
`3d9177a6cad7009e779d1b181c08e9b4641448f5` plus all 22 then-current changed/new paths,
including the uncommitted same-forest extension and corrected SEC-071 account-count wording.
The starting 924 build inputs matched the 6,574-test [checkpoint](../.v-sameforest-20261004-b72f/handoff.json);
its Judgement 51/path 9/selection 4 source was preserved, not replaced by the older format-48
production package, and the verified storage correction below advances only the Judgement format.
Preserve both original production-log snapshots, every prior verification artifact, the retained lab
setup, other checkouts and existing packages; use new isolated source/build copies with short
TEMP/TMP before discovery and rebuilt deliberate-defect/restored controls for new behavior checks.

**Owner-run proof-work lab checkpoint, 2026-10-04: completed, publication delay not reproduced.**
The [latest retained log](../.v-lab-log-20261004-8a91/run.log), SHA-256
`F82E9D766BDAD3E121888F6989B520709FF2C8C53AFFEE62F338858CA996C56D`, records all 18 rules
succeeding and publication completing for the same reported 8,441 objects, 381 descriptors,
11,189 entry positions and 459 selected questions, with no logged errors or cancellation.
The engine module identity `565f87a0-e143-46a4-af9d-0e5583db700e` matches the local Release build
and its 105 compiler-recorded source checksums; all 938 build inputs match the proof-work checkpoint,
and executable SHA-256 is `0A17811107120675C668AD2E705E0FB29CCC3C9B0710489B5117E6C34C71EF70`.
Judging completed in approximately 18 seconds, with proof writing at 1,422.3 ms; the new publication
breakdown completed in 285 ms, including generation sealing at 203 ms, path-fragment validation at
38 ms, database checkpointing at 16 ms and pending-manifest writing at 9 ms.
The earlier ten-second publication delay did not recur, so this run does not identify or prove a fix
for its cause; capture sealing again took 8.9 seconds versus 0.1 in the preceding run.
The log establishes successful current-build lab completion and working publication diagnostics,
not a controlled speedup, identical-answer comparison, production-scale memory acceptance or
attribution of the intermittent sealing/finalization delay.
No code, lab configuration or package was changed by this log review.

**Owner-approved proof-work and publication-diagnostics batch, 2026-10-04.**
After reviewing the target-preparation lab log, the owner approved reusing unchanged original-entry
fingerprints within prepared requester targets, reusing the path-node insert command, and adding
stage-only publication timings to explain the otherwise unattributed finalization delay.
Keep exact saved answers, fingerprints, formats, source/generation binding, original occurrences,
cancellation and durability unchanged; no object-level logging, UI change or new whole-run cache.
Use isolated offline work/allocation and correctness checks, rebuilt defects and restored controls,
then one final full regression; broader source/schema fingerprint redesign and cross-descriptor
interpretation remain later work, with no live access, timed campaign, production retry, packaging,
automatic build-identification change, commit or push.

**Proof-work and publication-diagnostics outcome, 2026-10-04: implemented and offline verified.**
Original-entry equality now reuses complete fingerprints and witness sets within each prepared
requester target, and path-node writes reuse the writer's existing statement helper; source hashes,
saved answers, original occurrences, ordering and all persisted formats remain unchanged.
Failed source reads cannot supply a partial cached set, numeric edge IDs cannot borrow another
prepared edge's originals, and ignored/cancelled node writes cannot commit a prefix.
Publication now records fifteen execution-only timing parts across source protection, final checks,
completion recording, indexing, database checkpoint/close, pending-manifest writing, generation
move/seal/selection and lock release, without object-level data or altered durability.
Failure and cancellation retain the active unfinished part; unavailable diagnostic logging does not
abort or retry the underlying publication.
The [validated checkpoint](../.v-proof-work-20261004-c24f/handoff.json) records 6,731 passing offline
tests in one final full regression, all 35 new cases plus one adapted boundary check detecting
19 rebuilt defects with restored controls, and 938 matching build inputs in the now-59-path
uncommitted working tree.
The synthetic matching control reads three originals once across 100 matches, and 2,000 warm
matches stay below 64 KiB of managed allocation; these are bounded work/allocation checks, not a
production runtime claim.
Judgement 52/path 9/selection 4, all 18 rules and all 38 historical layout hashes are unchanged.
The prior lab-tested engine and every earlier artifact were preserved during implementation; the
subsequent owner-run completion and publication breakdown are recorded above, while the earlier
ten-second delay remains unattributed because it did not recur.
Broader source/schema fingerprint reuse and cross-descriptor interpretation remain later work,
without UI/build-workflow changes, live access, timed campaigns, production retry, packaging, commit or push.

**Owner-run target-preparation lab checkpoint, 2026-10-04: completed and published.**
The [new retained log](../.v-lab-log-20261004-7e2a/run.log), SHA-256
`E2C8B516000634A68E8954B56D86AE11A8090C0F30C895F5465727834DEBD11D`, records all 18 rules
succeeding and the same 8,441 objects, 381 descriptors, 11,189 entry positions and 459 selected
questions as the preceding lab run, with no logged errors or cancellation.
The current target-preparation engine is confirmed by module identity
`f7fcd1f9-3058-4b21-b5b8-d497de0e5fbf`, matching local Release symbols and all 105 recorded source
checksums, with all 934 build inputs then checked matching the offline checkpoint; executable SHA-256 is
`B44237A32472657CC31292B294327C46EAE6E639B8F879E7EFECEF0DF559B319`.
Path preparation was 3,777.6 ms versus 5,861.9, requester permissions 729.1 versus 1,811.0,
combined checks 569.7 versus 1,880.4, and proof writing 1,608.9 versus 1,622.3 in the prior log.
However, final publication took approximately ten seconds, so total judging was about 29 seconds
versus 23; capture sealing also varied in the opposite direction, from 9.0 to 0.1 seconds.
These are two owner-run captures with matching reported counts, not a controlled same-evidence
timing campaign or proof of identical saved answers, production speedup or customer-scale memory safety.
Publication succeeded at 20:48:19 UTC; its final checks, indexing, checkpoint and sealing costs are
not separately timed, so the ten-second delay remains unattributed rather than blamed on one operation.
The owner requested continuing the remaining performance work, not automatic build identification,
live access, package replacement, a production retry, commit or push.

**Owner-approved target-by-target permission preparation, 2026-10-04.**
After the successful lab run, the owner chose to continue making audits faster and approved the
combined batch: shared target evidence for direct and combined requester-permission checks, plus
one source reading per target while validating original path witnesses.
Keep every account/resource/obtained-membership authorization independent, preserve every original
permission occurrence and witness check, exact source fingerprints, saved ordering, uncertainty and
generation binding, and release target preparation between batches instead of retaining a new
whole-forest permission cache.
Use fresh isolated offline answer/work-count tests, rebuilt defects and restored controls followed
by one final full regression; this does not approve general fingerprint redesign, cross-descriptor
interpretation, node-command cleanup, automatic build identification, UI changes, live access,
timed campaigns, production retry, package replacement, commit or push.

**Target-by-target preparation outcome, 2026-10-04: implemented and offline verified.**
Direct and combined requester checks now prepare permissions, holder source values and original
saved entries by exact target, retaining every independent requester/obtained-membership evaluation,
duplicate question, saved ordering and original source fingerprint.
Path-witness validation reads each exact target once and checks every original region and
ordinal/SID witness, without merging capture gaps, unsupported analysis, missing identities,
descriptor states or owner evidence.
Temporary grouping holds references to existing questions/witnesses; prepared permissions are local
to the active target batch, not a new whole-forest permission or verdict cache.
The [validated checkpoint](../.v-target-prep-20261004-9b31/handoff.json) records 6,696 passing offline
tests in one final full regression, all 62 new checks detecting 23 rebuilt defects with restored
controls, and 934 matching build inputs in the now-50-path uncommitted working tree.
A synthetic 32-question batch reads two target descriptors, and 4,000 path-witness occurrences
require two descriptor and two attribute reads while retaining all checks; these are verified work
counts, not measured production timing or memory savings.
Judgement 52/path 9/selection 4, all 18 rules and all 38 historical layout hashes are unchanged.
The previous lab-tested engine and symbols, original evidence/logs, prior verification attempts and
all owner work were preserved during implementation; the subsequent owner-run completion is recorded
above, while detailed saved-output/display and production acceptance remain outstanding.
General fingerprint reuse, cross-descriptor entry interpretation and prepared node inserts were the
next performance work at this checkpoint; exact-entry matching fingerprints and node inserts are
now covered by the proof-work outcome above.
No build-workflow change, UI change, live access, timed campaign, production retry, package
replacement, commit or push was performed.

**Owner-run lab checkpoint, 2026-10-04: the preceding two corrections completed and published.**
The owner paused implementation to test both efficiency corrections, then supplied the
[retained lab log](../.v-lab-log-20261004-d8c4/run.log), SHA-256
`826D2C3A7D51DBDB9A0035F6C514F6CDFF99BEB5B66A9EA403DF4AB9658F1313`.
Capture began at 19:16:14 UTC and judgement publication finished at 19:17:06 UTC: approximately
52 seconds for 8,441 objects across three domains, including about 23 seconds of judging.
All 18 rules report Succeeded, all 459 selected questions completed (215 requester permissions,
60 own-account memberships and 184 combined questions), proof writing completed in 1,622.3 ms,
and the final records explicitly say Completed and Published with no logged errors or cancellation.
SEC-071's `judged=8` is eight accounts assessed, not eight findings or individual permission questions.

The logged executable SHA-256 is
`3D2767ED4248A3DF38265C2AD0FD6BF82D2AA06ED2B73AB360DA4D964C7834FC` and engine module identity is
`e6cc0da9-3920-42ad-81de-2e883b020da6`; a read-only check matched that engine to the existing local
Release assembly and its bound compiler symbols, whose 105 recorded source checksums match the
verified membership-reuse checkpoint, with all 929 build inputs then checked matching that source.
The owner builds the tested Release executable in Visual Studio and wants confirmation of the exact
tested build to fit that workflow, rather than requiring manual source/build investigation.
This establishes that checkpoint's lab completion, not acceptance of the later target-preparation
batch, customer-scale memory acceptance, a controlled
before/after speedup, saved-screen correctness or a 4-6-hour production audit.
Path preparation was the largest logged path phase at 5,861.9 ms, but the log does not isolate its
individual costs; remaining efficiency recommendations and other unperformed acceptance checks stay open.
Only the supplied log and existing local build metadata were inspected: no agent-run AD operation,
new measurement campaign, packaging, code change, commit or push was performed.

**Owner-approved combined membership-reuse correction, 2026-10-04.**
The owner asked to combine related improvements to reduce session overhead while keeping correctness
first, and explicitly approved shared pre-change membership answers together with their common and
per-group input preparation.
Reuse only an identical account/group/permission-kind question within the same protected judging
attempt; keep subsequent permission checks, family-specific continuations, every saved answer and
source fingerprint unchanged, and release group-specific preparation after each batch rather than
retaining a whole-forest descriptor cache.
Use fresh isolated offline source copies, exact-answer and work-count checks, rebuilt defects and
restored controls followed by one final full regression run; no UI change, live access, production
retry, timed campaign, budget change, package replacement, commit or push is authorized.
The proof-storage checkpoint and all subsequent owner work remain preserved; general fingerprint
reuse, later source-witness reread reductions, entry interpretation and node-command improvements
remain separate work.

**Combined membership-reuse outcome, 2026-10-04: implemented and offline verified.**
One protected judging attempt now shares identical account/group/permission-kind pre-change answers
between standalone and combined checks, with common schema/domain preparation and group-at-a-time
permission/holder preparation; it does not share later authorization verdicts across resources.
Exact source-name lookup, original occurrence order, duplicate saved questions, source fingerprints,
family-specific continuations and missing/unsupported/unperformed distinctions remain unchanged,
with source-generation and cancellation checks still applied on reuse.
The [validated checkpoint](../.v-prerequisites-20261004-a63e/handoff.json) records 6,634 passing offline
tests in one final full regression, all 36 new checks plus one adapted identity-index check detecting
15 rebuilt defects with restored controls, and 929 build inputs matching the active source.
In the synthetic 16-account/two-group/two-permission-kind batch, 64 distinct questions require two
group-descriptor reads and four saved-edge selection queries; repeating those exact questions makes
no additional evidence or judgement queries, while separate questions retain separate answers.
These are verified work counts, not a production timing or memory campaign; no whole-audit runtime
saving or production acceptance is claimed.
Judgement 52/path 9/selection 4 and all 18 rules are unchanged, all 38 historical layout hashes remain
intact, and the original 38 uncommitted paths and proof-storage checkpoint were preserved beneath
the now-42-path working tree in the same checkout.
Requester-DACL preparation and per-witness descriptor rereads were the next work at this checkpoint
and are now covered by the target-preparation outcome above; general fingerprint reuse, entry
interpretation and prepared node writes remain later work.
Existing lab/display and new-judging-cancellation acceptance is unchanged, with no UI change, live
access, timed campaign, production retry, package replacement, commit or push performed.

**Owner-approved bounded proof-storage replacement, 2026-10-04.**
Save path calculation, node and requester-proof JSON incrementally as ordered, size-bounded database
fragments, with strict length, ordering and fingerprint validation and passive selected readback.
Preserve the exact JSON meaning, every original witness and saved answer, generation binding,
counting, uncertainty and atomic publication/cancellation; there is no screen change or result cap.
The practical cost is additional storage rows and a new Judgement format; older formats are refused,
not migrated, and path-calculation/requester-selection semantics are unchanged.
Verification uses fresh isolated synthetic/offline sources, capacity checks and explicitly rebuilt
defects and restored controls; production timing, original-bundle rejudging, live AD, package
replacement, another checkout, commit and push remain unauthorized.

**Bounded proof-storage outcome, 2026-10-04: implemented and offline verified, not production acceptance.**
Judgement 52 saves the same path calculation, node and requester-proof JSON in ordered fragments of
at most 64 KiB, with incremental writes/readback and strict completeness, ordering and fingerprint
checks; that fragment size is storage granularity, not a record or coverage limit.
Path calculation 9, requester selection 4 and all 18 rules retain their meanings, including original
occurrences, membership witnesses, generation binding, uncertainty, counts and passive selected pages.
The [validated checkpoint](../.v-proofstore-20261004-e91c/handoff.json) records 6,598 passing offline
tests, all 24 new behavior checks plus 20 related contract/readback cases detecting 15 explicitly
rebuilt defects with restored controls, 927 matching build inputs and all 37 earlier layout hashes
preserved.
The exact current header type saved **1,594,000,714 generated JSON bytes** in 24,323 fragments under a
256 MiB managed-heap ceiling with an independently checked full length and digest; the rebuilt
whole-value writer ran out of memory, and changed stored bytes were rejected.
Those two million occurrences repeat nine synthetic uncertainty witnesses, not a customer forest:
loaded result graphs and individual large scalar values still need memory, the precise production
payload/allocation remains unknown, and there is no production-completion or 4-6-hour runtime claim.
All owner work, original logs, packages, lab setup and prior artifacts remain preserved, including
failed verification attempts; broader reuse work and outstanding lab/display/new-judging-cancellation
acceptance remain separate, with no production retry, timed campaign, live AD action, package
replacement, commit or push performed.

**Owner-requested whole-audit efficiency review without coverage loss, 2026-10-04.**
The owner asked whether analysis can be made faster without truncating results or limiting coverage.
The review distinguishes already implemented descriptor sharing, prepared/batched object writes,
run-bound identity/membership indexes and automatic permission-led selection from remaining
repeated proof/source preparation, cross-family membership-prerequisite evaluation, per-witness
source rereading and whole-value proof serialization.
Reusing identical immutable inputs and answers, or staging every result in bounded writes, is not
permission to reuse an authorization verdict across different resources, requesters, membership
assumptions or generations.
The recommended trade-offs are additional storage/reference-management complexity and controlled
memory/disk use, not reduced evidence or certainty; no new implementation, performance campaign,
production-budget change or runtime guarantee is approved by this discussion.

**Production judgement failed during path-proof storage, 2026-10-04.**
The subsequent [failure log](../.v-production-failure-20261004-1452/run.log), SHA-256
`7726BCD36E5A220B1257DE367A8AAEBC27A89B27664E019BE42A52D458659750`, is the same executable,
evidence, derivation and judgement attempt as the partial snapshot below.
All 50,694 requester questions completed: 7,150 requester-permission, 28,790 own-account membership
and 14,754 combined questions; the combined batch finished at 14:50:27 UTC after about 71 minutes.
At 14:52:07 UTC, after **15 hours 44 minutes** overall and about 100 seconds of `WritingProofs`,
the attempt failed with `System.OutOfMemoryException`, `publication=NotStarted` and cancellation false.
No completed judgement was published by this attempt.

The stack identifies `JsonReaderHelper.TranscodeHelper` and `JsonSerializer.WriteString` called
directly by `Tier0PathStorage.Write`, not the incremental fingerprint buffer.
The failure-generation writer created JSON strings for individual nodes and a single calculation
header containing the selection and saved input/coverage projection; that same shape was present
in the source at the start of the bounded correction now verified above.
The whole-header allocation is the leading code-level suspect, but the stack carries neither a
source line nor allocation length, so the exact payload and physical-memory pressure are not yet
measured.
The identity-index correction addresses a separate repeated-work pattern; the storage replacement
above, not that earlier correction, removes whole-value materialization from this proof-writing path.

The recommendation is a bounded proof-storage memory correction and end-to-end performance
verification before another production attempt or further workload growth, preserving every
permission/membership witness, exact bindings, passive selected readback and explicit incomplete
results.
Do not substitute a RAM recommendation, silently drop large records, or equate the offline storage
correction with a proven successful production rerun.
Both log snapshots and original files are retained; this review performed no code change,
rejudging, recapture, AD operation, measurement campaign, package replacement, commit or push.

**Owner-reported production runtime concern and log review, 2026-10-04.**
The owner reports that the predecessor usually completed a whole new audit in 4-6 hours and is
concerned that much longer judging would prevent customers using this product.
This is a usability requirement to address, not approval to discard permission proof, silently cap
coverage or change production budgets.
The owner requested feedback on the supplied log only; no new optimization, measurement campaign,
production operation or package replacement is authorized by that request.

The [retained log snapshot](../.v-production-log-20261004-1435/run.log), SHA-256
`E5950891C819FACF240DFF1F05C0E5325BC773574708B4841ACFC22D0EB052F9`, starts the current judgement at
2026-10-03 23:08:00 UTC and ends at 2026-10-04 14:35:00 UTC: **15 hours 27 minutes**, with no
completed publication or ERROR/WARN line.
Its process fingerprint, `29CD08D7520CA2602F0FB7AABE7F79E057AFE8B614EE9C79E5B7EE7DF671D7A8`,
matches the package recorded before the nested-group slices; the format-48 baseline and its sources
are preserved separately from the current implementation.
The run binds judgement `d6f0fb2a-c7d2-4fc1-8381-55401c2d987e` to evidence
`9fbb1177cb4e33602dd5f9f2121845d38c9b435d6d80b9ffbaf04b7e898acbd2` and derivation
`119282fd-d97e-47f8-8cb5-6865b5e3a7e9`; the shared informational commit string alone does not identify
the executable's uncommitted source generation.

The 940,067-object pass took about 1 hour 58 minutes and processed 141,693,937 permission-entry
positions, followed by 7 minutes of scope selection, 37 minutes of detailed control assessment,
42 minutes of ownership assessment and 74 minutes of path preparation.
The earlier selection/matching corrections are visible: 50,694 questions for 5,621 accounts were
selected in 22.2 seconds, and matching the completed answer batches took 371 and 483 milliseconds.
The 7,150 requester-permission checks completed in 21 minutes; the **28,790 own-account membership
checks took 9 hours 29 minutes**, completing at 13:39:28 UTC.
The remaining combined family contains 14,754 questions by subtraction from the selected total;
at cutoff it had occupied about 55 minutes without a completion marker.
Subsequent proof writing, qualification, finding publication and sealing were still unconfirmed.

The preserved running-build code scans the entire identity collection to qualify each requester,
group and relevant holder, and rebuilds per-question source material; the combined family also
calls the own-account evaluator for its distinct prerequisite questions rather than consuming the
preceding family's answers.
These are code-confirmed repeated-work patterns, not a measured attribution of all 9.5 hours to
one function.
The newer implementation already replaces the operation identity scans with its run-bound index,
with work-count regression and rebuilt-defect evidence, but no same-workload production after-result
establishes the saving.
Heartbeat/object counters do not establish progress within the current combined batch or an ETA;
the completion at 13:39 is real progress and must not be described as an all-night hang.
A bounded performance-acceptance checkpoint before further workload growth is the recommendation,
not a newly approved optimization or production run; production evidence remains log-only.

**Owner-authorized same-forest permission slice and domain labels, 2026-10-04.**
Begin with ordinary users' already captured global/universal/domain-local group membership and
Modify permissions on fixed Tier 0 targets in verified domain naming contexts, including another
captured domain of the same forest.
Keep the membership-change families at their already tested boundary in this slice; do not expand
primary-group, SID-history, computer-actor or cross-forest authorization, and preserve the documented
configuration/schema resource-context limits.
The owner explicitly approved domain-qualified names on cross-domain results in the existing
account, target, granting-group and relationship labels, for example "Alice (ad.lab)" and
"Domain Admins (ba.ad.lab)", without adding panels or authorizing the larger presentation redesign.
Forest membership must come from the sealed run's declared domain scope, not from a shared DNS suffix.

**Same-forest captured-permission checkpoint — implemented and offline verified, 2026-10-04.**
Ordinary users' captured global/universal/domain-local membership can now support Modify permissions
on fixed Tier 0 targets in another verified domain of the same captured forest.
The declaration of read domains and each captured domain's SID/identity establish the context,
including domains in different DNS trees; a matching DNS suffix is not the evidence.
Global and universal nesting constraints are retained, domain-local groups apply in the resource's
own domain, and repeated BUILTIN SIDs resolve to that domain's captured group rather than the
requester's domain.
BUILTIN groups are supported as resource-domain holders, not transferable nested identities.

Normal GUI/CLI question selection, fixed High SEC-071, original permission entries and direct
membership witnesses, source/generation bindings and selected passive readback carry these results.
The approved existing labels show domain-qualified account, target, granting-group and relationship
names when the result crosses domains, without new panels or the deferred information-layout redesign.
The membership-change families remain at their preceding tested boundary; broader post-membership
resource contexts are not silently enabled by this captured-membership slice.
Primary-group, SID-history, computer-actor and cross-forest authorization remain unexpanded, and the
documented configuration/schema resource-context refusal remains intact.

Binding now compares a grant with the exact stored original entries rather than a display projection
that drops trustee detail, retaining the same counted permission record.
This fixes a false reference-unavailable result for BUILTIN and the already-supported SELF
substitution; it changes no generic-mask interpretation or permission-holder counting policy.
The [validated checkpoint](../.v-sameforest-20261004-b72f/handoff.json) records **6,574 passing offline
tests** after a final correct-source rebuild, with all **38 new and 29 adapted cases** detecting
assertion failures across **31 useful rebuilt defects**, and **33 passing restored controls** with
failed attempts retained.
Judgement format **51**, path-calculation version **9** and requester-selection version **4** carry
the extension; Evidence/Derivation formats, all 18 rules and historical layout hashes remain unchanged,
and format 51 retains format 50's physical tables.
The new same-forest results and labels have no live-lab or physical-display acceptance yet; the
earlier two slices' lab checkpoint remains valid, with no new AD operation, package overwrite,
measurement campaign, commit or push performed here.

**Owner-authorized source handoff to the lab machine, 2026-10-03.**
The owner installed VS Code on the lab machine and requested that all current product work be
committed and pushed to the repository so it can be downloaded there.
Publish the existing `stage7-completion` branch without merging or overwriting `main`; source,
tests and governing decisions travel together, while local verification folders, captured runs,
credentials and built packages remain excluded from Git.
The owner intends to authorize help with AD test setup and inspection on that machine; individual
live checks or changes still need a concrete lab scope, and this source handoff performs none.
Production remains owner-operated with run-log-only export, and combined lab and display acceptance
remain outstanding.

**Owner-authorized combined nested-slice lab campaign, 2026-10-04.**
The owner confirmed `ba.ad.lab` as the authorized laboratory domain and approved the bounded setup,
fresh capture and saved-result verification for the two completed nested-group slices, including
eight temporary test permission entries on the real BA Domain Admins object.
Use only the named isolated OU, ordinary test users and same-domain global security groups; preserve
separate existing-membership, Self-Membership, Write members, deny, loop, expected-administrator and
unrelated controls, with no test principal added to Domain Admins and no credential retained.
The owner explicitly requested that all test objects, memberships and permission entries remain after
testing for future campaigns; retain the manifest and rollback tooling, but do not perform cleanup
without a new request.
After the first capture showed the two deny controls also made unrelated positive checks explicitly
unknown, the owner approved a second isolated capture with only those two recorded deny entries
temporarily removed, followed by exact restoration so the retained lab setup finishes unchanged.

**Combined nested-slice lab checkpoint — live AD and saved results validated, 2026-10-04.**
The `ba.ad.lab` campaign passed 520 focused offline cases before live work, created the approved
23 marked objects, 13 memberships, three group permission entries and eight Domain Admins permission
entries, and retained that full setup exactly as the owner requested. The two fresh three-domain
captures each recorded 8,441 objects and 11,388 permission entries; after the isolated positive
capture, both deny entries were restored exactly once and the live Domain Admins DACL again matched
the completed setup fingerprint.

The deny-enabled saved result proves that the existing-membership and proposed-membership denies are
`NotEstablished` in captured entry order. The isolated positive result proves the existing nested
route, separate Self-Membership and Write members continuations, and terminating loop traversal;
normal GUI and CLI judging both completed all 18 rules with 34 findings, 13 accounts judged by SEC-071,
no unjudged SEC-071 accounts and the same seven High SEC-071 findings. The unrelated account has no
saved authorization, the expected administrator's 78 saved questions remain expected rather than
SEC-071 findings, and each of the six granting groups retains exactly one counted `WRITE_DAC` grant
regardless of members, route questions or the loop.

Protected passive readback verified the original permission entries, granting groups, direct
membership witnesses and exact Evidence/Derivation/Judgement bindings in both GUI and CLI results.
Saved paging returned every expected-administrator question without repetition, cancellation of a
saved read was honored, and all checked result files remained byte-for-byte unchanged; cancellation
of a new live judging attempt was not exercised. This is laboratory functional evidence, not wider
resource-context, production-scale or production acceptance.

The owner passed the findings screen on the laptop for readability and operation, but found the
amount of relationship-target information confusing and questioned how much of it an administrator
needs to see. Do not remove or regroup that evidence yet: the owner will review it on an external
monitor and then decide what should be pared down, so external-monitor acceptance and the concrete
presentation decision remain outstanding. No UI wording or layout change is authorized by this
checkpoint.

**Owner-authorized second bounded completion slice and lab plan, 2026-10-03.**
The owner requested "begin next slice" after the first slice and its passive lab check: implement one
obtainable own-account membership followed by captured same-domain global-security-group nesting and
Modify permissions on a fixed Tier 0 target, keeping Self-Membership and Write members separate.
The owner will prepare the lab to test the combined work after this slice; that planned test is not
yet acceptance or authorization for agent-operated live changes, rejudging, recapture or publication.
Reuse the approved presentation where accurate, retain pre-change authorization and post-change
ordered denies, and do not let the proposed membership authorize itself or become a second operation.

**Second bounded completion checkpoint — obtained membership through existing nesting, implemented and offline verified, 2026-10-03.**
The normal GUI and both CLI judging paths now select and save one supported own-account membership
outcome followed by captured same-domain global-group nesting and Modify permissions on a fixed
Tier 0 target.
Self-Membership and Write members remain different permissions, and the original permission to
obtain membership is checked before considering that membership.
The existing direct-user/single-global-group boundary for that initial permission remains; this
slice extends the continuation after it, not every possible way to obtain the first membership.

A group whose membership can be edited can now be admitted for assessment through its captured
nesting to the actual granting group, without classifying it as a fixed Tier 0 target or treating
membership alone as permission proof.
Saved results retain that assessment reason, each direct membership witness, both original
permissions, ordered existing and newly applicable denies, the actual granting group and exact
Evidence/Derivation/Judgement bindings.
Captured existing membership does not become a fictional Add, unknown current membership and
ordinary Add readiness remain explicit, and cycles do not add counted permissions or operations.
The same run-bound identity and membership indexes are reused across assessment, question selection
and permission proofs; no new forest-wide membership engine, processing limit or measurement
campaign was introduced.

The [validated checkpoint](../.v-obtained-nesting-20261003-f7b2/handoff.json) records **6,536 passing
offline tests** after the final correct-source rebuild, and all **54 new plus 20 adapted cases**
detecting assertion failures across **31 rebuilt defects with 31 passing restored controls**.
Judgement format **50**, path-calculation version **8** and requester-selection version **3** carry
the saved extension; Evidence/Derivation formats and the 18-rule catalogue remain unchanged, and all
earlier layout hashes, failed attempts, supplied lab files and verification checkpoints are retained.
The approved screen wording/layout is reused unchanged; owner-operated combined lab coverage,
physical-display checks and production acceptance remain outstanding.
Broader resource contexts, saved distance/route/coverage summaries and SEC-052 remain later Stage 7
work; no live directory operation, original-bundle rejudging, package overwrite, commit or push was
performed.

**Owner-approved bounded Stage 7 completion scope, 2026-10-03; begin in a fresh session.**
After the difficulty/usability assessment, the owner said "i agree with this" and requested that the
work begin in a new session while the current build is moved to the production forest for a new
judgement of the existing sealed capture.
The owner explicitly clarified that rejudging, not recapturing, is the intended production check.
Carry this approval forward without reopening the overall scope or treating it as approval to build
an unrestricted attack-path simulator.

- Extend concrete requester permission checks through supported captured nested security-group
  memberships, reusing existing membership/cycle facts and preserving relevant allows, denies,
  identity, resource scope and exact source bindings.
- Extend the existing one-obtained-membership model through supported existing nested memberships
  to a permission on a fixed Tier 0 target, keeping Self-Membership and Write members distinct.
- Add meaningful same-forest authorization contexts in bounded slices, including the applicable
  global/universal/domain-local group semantics; this is not a blanket promise of every cross-domain
  or cross-forest case, and unresolved resource context remains explicit.
- Complete saved distance, best-supported-route ordering and whole-run Tier 0/route/coverage
  summaries, preserving the distinction between a supported route's length and an established
  overall minimum, classified Tier 0 objects and other reachers, and findings and unresolved or
  unassessed work.
  This does not create Tier 1/2 classifications or change SEC-071's fixed High severity.
- Deliver SEC-052 circular-group findings as contained rule work over the existing persisted cycle
  product, including P-125's known self-referencing-group gap; cycle findings remain separate from
  proof of a route to Tier 0.

The first bounded implementation should be nested-group requester authorization in the existing
ordinary-user, same-domain context, before expanding resource contexts or adding another operation.
Preserve the captured direct membership witnesses rather than treating a flattened membership set
as sufficient proof of every permission.
General sequences of several hypothetical membership changes, arbitrary permission-rewrite and
account-takeover simulations, and exhaustive path enumeration are not this completion requirement.
Proven complete remediation remains Stage 8; P-143 and cosmetic UI redesign remain deferred.
Functional paging, cancellation and selected-only passive readback are part of usability, not
deferred visual polish.
Concrete new screen wording/layout, changed production budgets and new measurement campaigns still
need their own bounded approval; no new live operation, package overwrite, commit or push is
authorized for the agent.

**First bounded completion checkpoint — nested requester permissions, implemented and offline verified, 2026-10-03.**
Ordinary users' explicit captured `member` chains through same-domain global security groups now
support concrete `WRITE_DAC` (Modify permissions) checks on fixed Tier 0 targets.
The normal GUI and both CLI judging paths select these questions automatically; ordered allows and
denies, each direct membership witness, complete identities and exact source/generation bindings
remain in the saved proof, risk qualification, fixed High SEC-071 findings and selected passive readback.
The existing saved nesting walk is reused, with per-group member lookup and shared link/route evidence;
cycles do not add permissions, and member counts do not multiply group-held permission counts.

This slice does not extend own-account operations, primary-group or SID-history authorization,
universal/domain-local or cross-domain contexts, or computer actors.
It requires explicit group `member` witnesses; a primary-group link, `memberOf` alone or a nesting
step through a group carrying captured SID history is not promoted into this new proof.
Missing captured evidence, unsupported reasoning and unperformed work remain distinct, and existing
permission-reference refusals remain refusals even when membership or target-relative SELF is resolved.
No new screen wording/layout, processing ceiling, production budget, discovery activation or
measurement campaign was introduced.

The [validated checkpoint](../.v-nested-requester-20261003-c8e1/handoff.json) records **6,482 passing
offline tests** after a final correct-source rebuild, with all **51 new and 30 adapted cases**
detecting assertion failures across **38 useful rebuilt defects**, and **40 passing restored controls**
including the retained unsuccessful mutation attempts.
Judgement format **49**, path-calculation version **7** and requester-selection version **2** carry
the new proof semantics; Evidence/Derivation formats, all 18 rules and every historical layout hash
are preserved, with format 49 using format 48's unchanged physical layout.
The later approved completion items remain work, not delivered features; Stage 7, physical-display
acceptance and owner-operated log-only production acceptance are not declared complete.

**Owner-supplied nested-slice build lab run, checked passively, 2026-10-03.**
The supplied `ad.lab-20261004-011642` records completed judging of 8,418 objects in 28.3 seconds,
with 18 rules and Judgement 49/path 7/selection 2.
Its bundled executable is recorded as SHA-256
`3F2E2C5276B039704E932CC1ACF5162E6DF9BAFFA890409B9FF5AED427691BDD`, with judging-module identity
`8e9a71a3-c9d5-4d8a-955f-30bb04c360cf`; these are the owner's run identities, not a claim that its
published binary is byte-identical to the separate offline verification build.
All 337 saved questions for seven accounts read successfully on a fresh copy: 336 expected
administration answers and Barbara Hernandez's one High SEC-071 permission finding.
The [passive check](../.v-nested-lab-20261003-e40d/passive-lab-ready-result.json) verified three seals,
replayed no analysis and left all 16 original and copied files unchanged.

None of those questions contains a newly qualified nested-group permission route, so this run does
not supply a positive lab witness for the new slice; the synthetic/offline verification remains its
positive evidence.
The saved broader coverage limitations and 42 questions with unknown current membership/ordinary Add
readiness remain explicit, and this is not production-scale or physical-display acceptance.
No subsequent implementation was started during that lab check; the second checkpoint above records
the later implementation of the already-approved obtainable-membership continuation.

**Session-entry baseline and preservation.**
Continue in the existing `C:\Users\jistrand\source\repos\SecureAD.Next-stage7` checkout on
`stage7-completion`, HEAD `98cd4d094326ec8ff2719c321da5d759e7a11a99` plus all current uncommitted
work, not the bare commit; 84 changed/new paths were inherited at this session's entry.
At entry, all 912 executable-source files matched the preceding
[verified checkpoint](../.v-sec071-admin-20261003-a4c6/handoff.json), with 6,431 passing offline tests
and 53 rebuilt defects/restored controls; that checkpoint and its tested sources remain historical evidence,
not a replacement for the newly verified current files.
Do not create another checkout/worktree, alter the owner's other checkouts or rebuild/publish over
existing lab/production outputs.
Preserve all prior verification and evidence, including `.v-sec071-20261003`,
`.v-requester-reuse-20261003` and `.v-sec071-admin-20261003-a4c6`.
Use isolated source/build copies for verification, short source paths where the unchanged fixtures
require them, and fresh short TEMP/TMP before test-assembly loading or discovery; retain failed
attempts, mutation-test new behavior in isolated sources, rebuild defects and restored controls
explicitly, and finish with a correct-source rebuild.

**Owner-confirmed completion order, 2026-10-03: finish the remaining Stage 7 analysis before rules.**
The owner explicitly declined closing Stage 7 as only the three currently supported families:
finish the wider supported path combinations and remaining distance/tier summaries first, so the
judging workload being accepted represents the completed stage rather than a smaller implementation.
This is a delivery priority, not measured evidence that path analysis is the largest runtime cost.
P-143 customer-declared assets are deferred until after the main feature/rule work and no longer gate
Stage 7 completion; its entry workflow remains undecided, and future rules must continue to use the
shared authoritative Tier 0 definition rather than introducing private lists.

The owner likes the corrected SEC-071 information in the supplied lab screenshot, but describes the
presentation as a "white wall of text"; a modern visual redesign is deferred until the main features
work, not approved as the next session.
This is positive owner feedback on the displayed information, not acceptance of every physical
laptop/external-monitor check.
The owner is moving the lab-tested build to production to rejudge the existing sealed capture and
check whether judging time improves; recapture is not planned for these analysis/presentation changes.
Keep the original evidence, previous results and logs preserved, and identify the build and retained
derived inputs when comparing timings.
No new production result is reported, and a timing for the current families does not establish the
cost of the remaining Stage 7 analysis.
Production validation stays owner-operated and log-only; no agent-operated live access, package
overwrite, new measurement campaign, commit or push is authorized by this discussion.

**Earlier blocking priority, 2026-10-02: get production-scale judging to finish before further
Stage 7 work, new rules or UI performance/redesign.** The owner cannot complete that work while a
production-sized judgement fails. The bounded memory correction below builds on the verified,
uncommitted input-reuse work rather than restarting that completed investigation.
Getting past one exception is a checkpoint, not acceptance: judging must finish, publish its exact
source-bound result and reopen it correctly at representative scale. Small-fixture gains alone do
not meet that goal, and no customer-runtime ceiling has been agreed. This priority does not itself
approve a new implementation scope, measurement campaign, publication or production retry.

**Owner's three-day demonstration deadline, 2026-10-02:** review further improvements and prepare
future publishing while the owner publishes and tests the verified `4deef9f` baseline.
The owner requested follow-up work on a new branch rather than holding all preparation for the
production result; use a separate checkout so the Visual Studio checkout and its test build do not
change underneath him.
The current follow-up is `p280-judging-followup`, including repeatable normal Release publishing
and a review of remaining judging/completion/readback risks, not a restart of the completed benchmarks.
Specific optimization and measurement scopes still require bounded approval; preserve permission
answers, bindings, incompleteness and historical evidence, with no new UI presentation, production
operations, commit or push authorized by this request.

**Owner-reported browsing usability, 2026-10-02:** the owner reports that browsing the current
implementation is unusably slow even in the small laboratory, not only at production scale.
This is a usability observation, not a measured timing or identification of the exact running build.
The existing calculate-once/stored-readback requirement remains in force across completed-result
browsing; faster judging alone does not establish that the application is usable.
The proposed larger correction must consider both result production and selected-result reading,
while keeping the known whole-forest saved-path read separate from unconfirmed causes of other
screen delays.
This clarification does not approve a broader implementation, presentation change, measurement
campaign or change to the owner's current production test.

**Owner direction, 2026-10-02: ready to start the larger correction.**
The owner wants the coordinated calculate-once/result-production and selected-result-reading fix,
not another sequence of disconnected optimizations, and asks for navigation performance logging
like the predecessor's if that data is needed.
Use the existing separate checkout and preserve its verified uncommitted work; keep the active
Visual Studio checkout, running judgement and historical evidence untouched.
The concrete implementation/verification boundary and any visible loading or warning presentation
still need to be stated before editing those surfaces; no live access, production retry, commit or
push follows from this direction.

**Owner-approved coordinated implementation scope, 2026-10-02.**
Carry prepared evidence, saved-proof references and writing state through later judging stages;
replace unnecessary whole-forest selected-result reads, preserve the protected open-run lifetime,
and keep slow reading off the UI thread.
Add local navigation diagnostics covering the action, run/build identity, opening/checking, queries,
time until results are applied, and success/refusal/cancellation, without live-directory access.
The owner explicitly approved Dashboard wording **"Loading saved results..."** and
**"Saved membership results could not be read."**, rather than reporting failed reads as absent
derivation.
Saved-path limitations use 100-entry pages, matching object listing, with
**"Showing X-Y of Z saved limitations"** and Previous/Next controls; retain every limitation and
the distinction between missing captured evidence and unsupported analysis.
This is a display page size, not an analysis budget.
Approval includes exact-answer/fingerprint equivalence, source/generation and cancellation
regressions, explicitly rebuilt isolated defects and correct rebuilds, and bounded fresh offline
comparisons of judging, reopening and selected-view reads with a five-minute stop per invocation.
Do not expand inconclusive measurements automatically or claim production acceptance from small
fixtures.
Use the separate checkout, preserve existing follow-up work and failed attempts, and do not change
the running judgement, original checkout, rules, Tier-0 policy or discovery settings; no production
retry, commit or push is authorized.

**Owner-approved navigation-logging correction, 2026-10-02.**
The owner approved replacing navigation's repeated executable hashing with one successful
fingerprint calculation per running application, retaining that exact fingerprint in every entry.
Keep each action's run, evidence and judgement-generation identity and outcome independent;
this is not a cache of saved results and does not remove any captured-evidence verification.
The first navigation can still pay the one-time identification cost, which remains included in
its recorded total; subsequent navigation must not read the executable again for logging.
Use bounded offline verification with rebuilt isolated defects, preserve the supplied lab log,
and do not infer publication, a new lab/production measurement run, commit or push approval.

**Owner direction for risk-first path presentation, 2026-10-02.**
The owner rejects the raw whole-analysis diagnostic block in the normal object view:
**"this is a security audit tool, the user need to know where risk is."**
The normal presentation must lead with the selected object's supported security risk and the
permission, membership or ownership evidence behind it, not thousands of serialized uncertainty
records from across the run.
Relevant missing evidence, unsupported analysis and work that was not run still need concise,
plain-language explanations; removing the diagnostic block must not turn an unknown answer into
"no risk" or turn an expected administrative relationship into a security finding.
Keep the underlying saved proofs and coverage records intact.
This establishes the product direction, not approval of a particular replacement layout, new path
semantics, requester activation or a restarted measurement campaign; the existing Stage 7 completion
requirements and bounded approval boundaries below remain in force.

**Owner rejection of the positive SEC-071 presentation, 2026-10-03.**
The owner supplied `ad.lab-20261003-192529` and a screenshot, reporting that the route's
**From/To** distinguished names read as "change Barbara to DC" rather than explaining her permission.
The owner requires actionable administrator wording, exemplified by removing **Modify permissions**
from Barbara, and explicitly rejects raw JSON as user-facing supporting evidence.
The screen must name the affected account, permission, actual target and place where the grant
can be changed; a domain distinguished name must not read as a domain-controller computer.
This supersedes treating generic guidance and expanded serialized proofs as an adequate SEC-071
presentation, while leaving the saved proofs, rule semantics and severity unchanged.
The approved replacement below is implemented and offline verified in the existing
`stage7-completion` checkout; existing lab and production packages remain unchanged.

Read-only inspection of that sealed lab run verifies one High SEC-071 finding for `bhernandez`,
with a direct, non-inherited allow entry on the `ba.ad.lab` domain object, applying to that object
only and including `WRITE_DAC`.
The entry also contains other rights, so removing the relevant **Modify permissions** right must
not be phrased as deleting every permission in the entry without separate review.
The run completed judging in 28.0 seconds with 28 total findings; all three seals and the unexpected
question/source fingerprints verify, and all 16 supplied files remained unchanged.
No permission was changed, no analysis replayed and no production operation performed during review.
Permission-specific change guidance must not claim a proven complete fix for every route or mark a
finding resolved without new captured evidence.

**Owner-approved SEC-071 administrator presentation correction, 2026-10-03; implemented and offline verified.**
The owner selected **"Approve for the next implementation session"** for the following bounded
wording/layout correction, preserving the current uncommitted work and lab/production packages.
The subsequent **"implement"** authorizes this exact correction, followed immediately by the owner's
request to continue in a fresh session because the current context is long.
Carry that approval forward without asking again, work in the existing `stage7-completion` checkout,
and preserve all current working files rather than restoring `98cd4d0` over the uncommitted changes.
No UI implementation was begun before this handoff.
For the supplied Barbara case, the approved presentation is:

> **High · SEC-071**
>
> **Barbara Hernandez can change permissions on the ba.ad.lab domain**
>
> **Recommended change**
>
> Remove **Modify permissions** from **Barbara Hernandez's explicit permissions** on
> **ba.ad.lab (domain)**. Keep the entry's other permissions unchanged unless they are separately reviewed.
>
> **Where to change it**
>
> Active Directory Users and Computers → ba.ad.lab → Properties → Security → Advanced →
> Barbara Hernandez's entry → Edit → clear **Modify permissions**.
>
> **Why this is a finding**
>
> The captured permissions allow Barbara to change this domain object's permissions, but the
> captured evidence does not establish an expected administrative role for her on this domain.
>
> **Scope of this recommendation**
>
> This addresses the permission shown, not every possible route. A new capture is needed to verify the change.

Remove the **From/To** block, duplicate **Supporting evidence** sections and all raw JSON from
administrator-facing SEC-071 evidence.
Use one **Permission details** section with the following labelled information:

| Field | Supplied Barbara example |
|---|---|
| Account | Barbara Hernandez (`bhernandez`) |
| Target | ba.ad.lab — Domain |
| Relevant permission | Modify permissions (`WRITE_DAC`) |
| Granted to | Barbara Hernandez directly |
| Assignment | Explicit; not inherited |
| Applies to | This object only |
| Permission check | Allowed |

Show relevant captured allow/deny entries and membership evidence as labelled rows and sentences,
not serialized records.
Exact directory names, SIDs, object identifiers and saved-run identity remain available in a collapsed
**Record details** area as labelled fields, also without JSON.

- Apply readable relationship wording to all three currently supported SEC-071 families: direct
  permission, existing membership and supported own-account membership followed by permission.
- For group-held or inherited access, name the actual granting group and source rather than telling
  the operator to remove a direct user grant that does not exist.
  Explain when a change affects other members or descendants, or when the original grant location
  is not established.
- Keep missing evidence and unknown membership/Add prerequisites explicit in plain language;
  an uncertain operation must not become a claim that it succeeded.
- Keep finding identity, High severity, risk classifications, independent counts and paging unchanged.
  Read only selected saved results, preserving original proofs and exact generation bindings.
- This is permission-specific guidance, not automatic AD remediation or a new engine claiming a
  complete fix across all routes.

Verify the supplied case and synthetic direct/group/inherited/unknown cases, readable evidence,
exact permission wording, cancellation and laptop-sized layouts with rebuilt negative controls.
Preserve the supplied image/bundle, existing work and lab/production packages.
No directory change, recapture, original-bundle rejudging, new measurement, package overwrite,
commit or push is included.

**Validated checkpoint, 2026-10-03:** the [retained handoff](../.v-sec071-admin-20261003-a4c6/handoff.json)
records 6,431 passing offline tests after the final correct-source rebuild, with assertion witnesses
for all 32 new and 15 adapted behavior cases across 53 rebuilt isolated defects and passing restored
controls.
The supplied positive case matches the approved headline, permission-specific change and editor
location on a fresh copy, with three verified seals, no analysis replay and all 16 copied files unchanged.
Its explanation uses the full captured name and "this account": this capture does not supply a given
name or pronouns, and neither is guessed from the directory name.
Original evidence and image, prior verification artifacts and both other checkouts/packages remain
unchanged, and the owner's pre-existing work is preserved; physical laptop/external-monitor checks
and owner-operated, log-only production acceptance remain outstanding, with no publication, commit
or push performed.

**Owner clarification: findings must represent risk, not ownership inventory, 2026-10-02.**
After the computer-owned Windows Virtual Machine service record was shown as SEC-031, the owner
stated that this creates noise and that expected ownership must be established and excluded from
findings.
A technically correct ownership capability is not, by itself, sufficient justification for a
risk finding; retain the captured ownership and permission evidence even when a supported
expectation excludes the relationship from findings.
This supersedes the earlier SEC-031 justification that the self-owned service-record pattern
necessarily belongs in findings merely because its non-administrative ownership is real.
It does not approve blanket exclusions for computer accounts, service accounts or service-connection
points, and uncertain expectedness must not be silently treated as expected.
Clarify Stage 7 completion before starting finding tuning; the existing Stage 7-first delivery order
remains, with concrete expected-ownership criteria, implementation and presentation still requiring
a bounded proposal rather than being inferred from this direction.

**Owner-confirmed path-analysis outcome and continuation, 2026-10-02.**
The owner confirmed that the goal is one coherent, automatic analysis of unintended control leading
to Tier 0, not a permission inventory presented as findings or a menu of separately requested paths.
Connect the supported membership, ownership, permission and operation evidence into justified chains;
the three currently exercised requester families are a foundation, not the completion definition.
Expected administration must be distinguished from risk without erasing relationships an unexpected
principal could use, and missing evidence or unsupported reasoning must remain explicit.
Valid independent security-rule findings remain separate from path findings; proven source-action
remediation, reports and run comparisons remain the later product stages already specified.

The owner will take a build to the production environment, rejudge there and return **only the run
log**; no other production data can be exported.
Do not request bundles, databases, proof dumps, separate summaries or other exports, or work around
that boundary by adding object-level data dumps to logging.
The log can establish recorded execution, build/generation identity, timings, failures and recorded
readback outcomes, but phase completion alone does not prove nonempty requester work, every saved
answer, or complete production acceptance; further checks must remain on site and be explicitly
approved if needed.
This is owner-operated validation, not permission for the agent to access AD, replay production
evidence, restart paused measurements, expand logging or change production budgets.

Continue implementation preparation in `stage7-completion` at
`C:\Users\jistrand\source\repos\SecureAD.Next-stage7`, independently of that production run.
The existing `p280-judging-followup` checkout remains the owner's build source, with its uncommitted
RID 498 correction preserved; do not change it or its published executables underneath the owner.
The separate checkout carries the same verified code and preceding documentation changes without a
new commit, while historical evidence and verification artifacts remain in the original checkouts.
The next Stage 7 implementation still needs a concrete bounded scope; this continuation does not
approve general finding tuning, new screen wording/layout, further optimization, commit or push.

**Production-check workflow clarification, 2026-10-03 (P-110).**
The current GUI offers **Derive facts** only for sealed evidence with no existing analysis;
it cannot rebuild facts for an already derived run.
**Discard judgement and judge again** deletes only saved judgements and invokes judging against
the retained evidence and derived facts, keeping the log; cancellation or failure can therefore
leave no completed judgement to reopen.
This judgement-only workflow can exercise the new Stage 7 requester analysis without rederiving,
but does not apply the RID 498 correction to an older saved protection catalogue.
Do not make the independent catalogue correction or missing GUI refresh action a prerequisite for
that requester check, or describe judgement-only output as testing refreshed derived facts.
The CLI's separate derive command exists, but no new GUI workflow, manual deletion, recapture or
agent-operated production run is authorized by this clarification.

**Owner-reported production preparation, 2026-10-03.**
The owner moved both existing derivation and judgement files into another folder, reopened the GUI
and was then offered **Derive facts**, with judgement to follow.
This is an owner-operated refresh of both implemented analysis stages from the retained capture,
not a new GUI refresh feature or permission for the agent to move production files.
The refreshed run can exercise the current protection catalogue as well as requester analysis, but
its outcome is still to be established and it cannot verify Stage 7 features not yet implemented.
Only its run log may be returned, and development continues independently in `stage7-completion`.

**Owner-supplied partial production log and planned lab test, 2026-10-03.**
The owner reports that the overnight judgement is still unfinished and supplied
`C:\Users\jistrand\Downloads\new\run.log`, with older derivation/judgement sections removed for
readability; use the new analysis markers rather than the original capture date for elapsed time.
The supplied excerpt identifies the preserved format-46 production-test executable by its recorded
fingerprint, with 17 rules and 940,067 objects, starting judgement at **04:30:12 UTC** and still
reporting status at **15:46:13 UTC**.
Its last completed requester subphase is **PreparingPaths at 08:30:26 UTC**; the matching code places
the following uncompleted interval in account/question selection, but the log does not identify an
inner hot function, establish continuing progress or provide a completion forecast.
The owner will test the new SEC-071 candidate in the laboratory independently of this production run.
That is not production performance acceptance or authorization for agent-operated lab/production
access, optimization, new measurement tooling/runs, extra logging or changing the running package.
Compared with this production package, the candidate adds both saved risk qualification and SEC-071
publication; its correctness verification does not establish their incremental production runtime.

**Owner-operated corrected-build lab run, supplied 2026-10-03.**
The owner supplied `C:\Users\jistrand\Downloads\ad.lab-20261003-184702` for read-only inspection.
Its Release executable fingerprint is
`31195D043235EDC59B58BB16EF533F621F57E2E9A6F5FB0D975A1E17B89EDFB1`,
with judgement-engine MVID `8fa900d7-938e-42c5-93cc-9b0ed5dbf254`.
The run captures 8,418 objects across `ad.lab`, `ba.ad.lab` and `ph.ad.lab`, completes derivation in
2.8 seconds and judging in 29.3 seconds, and publishes judgement
`919487dc-82a1-4542-990f-4d9b3e2f73dc` against derivation
`186898a4-b81b-4408-8316-f91f8c61c3a8`.
The new diagnostics establish that the corrected selection/matching code ran: the whole selection
phase took 258.1 ms (246 ms inside its diagnostic scope), indexed all 8,418 identities and completed
48 resources, producing 336 distinct questions for six accounts.
The three answer batches retain 92 requester-permission, 60 own-account membership and 184 combined
answers, with matching scopes totaling approximately 42 ms.

SEC-071's finding-publication work took 153 ms, not the entire path-analysis or qualification cost.
All 336 saved qualifications are expected same-domain administration, so the rule ran but emitted
no SEC-071 finding; 27 separate-rule findings remain.
All three database seals, every saved question/source-proof fingerprint and their evidence,
derivation and calculation bindings were checked read-only, and all 16 supplied files, including
database sidecars, remained byte-for-byte unchanged.
The log records successful saved findings and Tier-0 section navigation, including a 68.1 ms Tier-0
read, but does not establish a new-process reopen or physical-display acceptance.

This run does not establish forest-wide safety: saved path coverage still distinguishes incomplete
inputs from unsupported analysis, and 42 own-account questions retain unknown current membership and
ordinary Add readiness under the existing two-case proof.
Read-only clarification of those 42 answers: 21 use Self-Membership and 21 use ordinary Write Members,
and the applicable permission is established in every case; these are questions, not 42 accounts or
failed directory modifications.
The saved issues include `MembershipStateUnknown` and `LiveOperationNotEvaluated`, because not seeing
the account's membership value is not treated as proof of absence.
The two-case answer means membership is already available if present, or the supported permission
allows adding the account's own value if absent; it does not assert that an ordinary Add is ready or
that any live operation succeeded.
All 184 combined lab answers use existing membership; a positive SEC-071 finding and hypothetical
new-membership combinations remain covered by synthetic verification rather than demonstrated by
this captured run.
This is useful packaged lab execution/readback evidence, not a controlled before/after timing
comparison, a forecast for the 940,067-object production capture, or production acceptance.
Any production retry remains separately authorized, owner-operated and log-only.

**Owner-approved requester repeated-work correction, 2026-10-03; implemented and offline verified.**
The owner selected **"Approve for the next implementation session"** for one coordinated correction
to account/question selection and matching its saved answers back to objects.
The subsequent **"begin implementation"** authorizes that recorded correction now, without expanding
its measurement, production, package or publication boundaries.
The owner asked whether the overnight production run must continue: it is not a prerequisite for
this correction, and normal application cancellation with the log and run files retained was
recommended, not agent-operated termination or a claim of production acceptance.
Whether the owner actually cancels the run is not yet reported.
The final correct-source rebuild in an isolated short-path source copy passes **6,399 offline tests**
with coverage, and all **31 new behavior/work-counter cases** detect assertion failures across
**17 rebuilt isolated defects** and pass restored controls.
The [verified correction checkpoint](../.v-requester-reuse-20261003/handoff.json) retains the prior
source/binary baseline, independent earlier-algorithm references, failed attempts and exact build
provenance; the seven retained lab-baseline binaries and all 27 published files remain unchanged.
The saved format remains **48** and no security semantics, scope, numerical analysis budget or UI
wording/layout changed.
These checks establish removal of the repeated work and preservation of answers, not a measured
production runtime reduction or completed production acceptance.
Start from the current uncommitted SEC-071 working files in the existing `stage7-completion`
checkout, not by restoring the bare `98cd4d0` commit or a verification snapshot over subsequent work.
The owner-operated SEC-071 lab test remains separate, and its baseline and package must be preserved.

- Build one identity lookup for the current bound run, keyed by security identity and domain scope,
  instead of scanning the entire path-node collection for each qualification.
  Duplicate or unresolved identities remain unresolved; never select whichever object appeared first.
- Work out each group's relevant target-permission references once and reuse those references when
  selecting questions for its members.
  A group's permission is not the member's authorization: every required account-specific permission
  and membership check still runs with its original resource and pre-change/obtained-membership context.
- Reuse each account's unchanged fingerprint and accumulate duplicate supporting references without
  repeatedly rebuilding growing lists.
  Retain every original witness, the existing deduplication meaning and output ordering.
- Index saved answers by the correct requester identity before matching them back to objects, rather
  than searching whole proof lists for each object after every family.
  Preserve the existing route-choice and tie-breaking rules, permission classifications, expectedness,
  SEC-071 findings, independent holder/account/question counts and explicit incomplete outcomes.

Reuse the existing periodic diagnostics for aggregate-only log progress covering
**"Selecting account checks"** and **"Matching saved answers"**.
Report the current step, resources processed/total, distinct access checks selected, answers processed,
elapsed time and completed/cancelled/failed status, with the existing build/run/generation identity.
A resource here means a group or target being examined.
Add no account names, SIDs, object names or proof dumps, and change no screen wording or layout.
These counters describe execution progress, not security-analysis completeness.

Verification compares before/after questions, witnesses, permission answers, findings and independent
counts on offline fixtures under properly bound generations.
Work-count regression checks must prove that more questions do not cause another full-object scan per
question, another full-target scan per member or another full-answer scan per object.
Exercise ambiguous identities, domain scope, duplicate evidence, cancellation and failed publication,
with explicitly rebuilt isolated deliberate defects and restored controls, then a correct-source
rebuild and the existing offline regression suite.
Preserve historical fixtures, hashes, failed attempts and prior verification records rather than
changing expected values to bless a different answer.

The accepted engineering trade-off is temporary lookup memory for the duration of the run, referencing
existing data rather than copying whole evidence or proof objects.
This removes avoidable repetition, not genuine required work, and does not promise a particular runtime
reduction or accept production scale.
No new checkout, analysis limit, security-semantic change, measurement-campaign restart, live access,
production retry, publication, commit or push is authorized.
Do not overwrite the production-test or lab package.
The already-running process cannot benefit from a code change; any later production test remains
separately authorized, owner-operated and log-only.

**Owner-approved SEC-071 findings and minimum risk-first readback, 2026-10-03.**
The owner selected **"Approve this proposal for the next implementation session"**.
This approves the following bounded scope, wording and grouping, not implementation during the
proposal session or completion of Stage 7.
The owner's subsequent **"begin"** authorizes implementation of this recorded slice; it does not
expand the scope or the separate production, measurement and publication boundaries.
**Status: implemented and offline verified in judgement format 48.**
The final correct-source Release rebuild passes all **6,368 offline tests**, with coverage witnesses
for the new components; all **55 selected new or changed behavior and public-contract cases** detect
assertion failures across **31 rebuilt isolated defects** and pass restored controls.
The [verified checkpoint](../.v-sec071-20261003/handoff.json) retains failed attempts, source/build
identity and preservation checks, including the unchanged production-test executable and all earlier
layout hashes.
Physical laptop/external-monitor checks and representative production acceptance remain outstanding;
no measurement restart, production operation, application publication, commit or push occurred.
Continue from `98cd4d0` on `stage7-completion` in the existing
`C:\Users\jistrand\source\repos\SecureAD.Next-stage7` checkout; do not create another checkout.

- Produce SEC-071 automatically during normal GUI/CLI judging, after the existing saved
  qualification, from every qualified unexpected result across requester permission, own-account
  membership, and membership followed by requester permission.
  Do not add path combinations or change qualification, permission semantics or the authoritative
  Tier-0 definition.
- Produce one finding per affected account for the overall Tier-0 control plane, following the
  [canonical identity specification](specs/JUDGEMENT-HALF.md).
  Multiple destinations and supporting questions belong under that finding rather than producing
  duplicates; its identity survives route and account-name changes.
  Use one fixed **High** severity for SEC-071, with no severity split or grading by path length.
- Expected routes, unresolved answers and questions that did not establish a route remain saved
  but produce no SEC-071 finding.
  An expected route must not hide another unexpected route for the same account, and merely being
  a Tier-0 target is not a finding.
- Save findings, supporting proof references, rule-execution status and whole-run counts with the
  same evidence and analysis generation; cancellation or validation failure must not publish a
  partial result.
  Opening a screen reads only saved results for the selected account and never reruns analysis.
  Account, access-check and group-held permission counts remain independent, and displayed pages
  must not supply whole-run totals.
- Retain original permission, membership and ownership evidence, captured membership and the
  separate state of ordinary Add prerequisites.
  An unresolved prerequisite remains unresolved rather than becoming proof that an operation or
  takeover succeeded.

Reuse the existing **Findings** screen, keeping severity ordering and filters, with this compact,
explicitly whole-run summary:

> **Whole-run Tier 0 summary**
>
> **Accounts with SEC-071 findings: {N}**
>
> **Unresolved access checks: {U}**
>
> Supported checks only; other routes may exist.

An access check means one saved question about an account's access, not a distinct account or a
unique route.
Counts come from the complete saved result, not the displayed page; missing or unperformed analysis
shows its status instead of zero.

Rename the existing **"Saved Tier 0 path"** section to **"Tier 0 findings and routes"**, with no new
top-level screen.
A SEC-071 finding offers **"View saved routes"**, opening that same account-specific section.
The approved grouping and order are:

| Group | Default presentation |
|---|---|
| **Unexpected routes** | Open first: finding, reached target, why authority is unexpected, readable steps, then expandable supporting evidence. |
| **Unresolved access checks** | A concise warning when present, distinguishing missing captured evidence, unsupported analysis and unfinished work. |
| **Expected administration — not findings** | Collapsed, preserving the relationship and its evidence. |
| **Other completed checks — no route established** | Collapsed, explicitly not a safety verdict. |

Finding heading:

> **SEC-071 — Unexpected route to Tier 0**

Explanation:

> The saved evidence establishes a supported route to Tier 0 outside this account's expected
> administrative authority on the reached target.

Boundary:

> Saved permission, membership and ownership evidence is not proof of account takeover or a
> successful live operation.

Show existing membership and whether the prerequisites for adding the account to a group were
established or remain unresolved wherever relevant.
Label a displayed route **"Saved supporting route"**, not "best route", "shortest attack" or a complete
fix; all supporting questions remain accessible through paging.

When assessed questions produce no finding:

> No SEC-071 finding was established by these checks. This does not establish that no route exists.

When none were recorded:

> No saved access checks for this object. This does not assess accounts that may reach it.

Retain explicit existing not-run, unavailable, unfinished and wrong-generation refusals.
Replace the whole-analysis raw diagnostic block with concise relevant explanations while preserving
the underlying records, and keep a selected object's existing Tier-0 classification informational
and separate from findings.
The new rule's **"What to do"** guidance is:

> Review the recorded permission or membership relationship and its scope before making changes.
> This finding does not establish a complete remediation for all routes.

Verification covers duplicate-free stable account identity, all-question coverage, mixed expected
and unexpected cases, exact independent counts, operation-readiness caveats, publication rollback
and passive generation-bound reopening.
Use offline fixtures and rebuilt isolated deliberate-defect checks for every new behavior check,
with explicit correct-source rebuilds, preserving frozen values, historical evidence and failed
attempts.
Include normal layout checks; any unperformed physical-display checks remain outstanding.

This requires saved finding/evidence integration, not just wording, and older saved analyses are
not rewritten or migrated.
No broader path composition, declared-asset work, incoming-route browser, remediation engine,
SEC-031 or general finding tuning, dashboard redesign, new budgets, measurement restart,
production operation, package change, new checkout, commit or push is authorized.
Preserve the production-test checkout/package and historical evidence; production validation remains
owner-operated.
Only its run log may leave that environment; do not add object-level export logging.
Stage 7 completion and production acceptance remain separate and outstanding.

**Owner-approved saved path-risk qualification checkpoint, 2026-10-03.**
Qualify every saved question in the three existing concrete-requester proof families against the
requester's captured, pre-change authority on the actual reached target, reusing the existing scoped
control-plane policy.
Save a proven unexpected route, a proven expected route, a route not established for that question,
or an unresolved answer; none is a whole-forest safety verdict.
Do not inherit expectedness from a granting group, use obtained membership to justify its own
escalation, hide out-of-scope control because the requester is Tier 0 elsewhere, or inspect only the
route selected for display.
Keep original permission and operation proofs, ordinary Add readiness, current membership,
generation binding and group-held permission counts independent.
This checkpoint saves qualification for later SEC-071 production but emits no findings and changes
no screens, path combinations, Tier-0 definition or permission semantics.
Use synthetic/offline verification and preserve historical data and the owner's production-test
checkout/package, with no production access, measurement campaign, commit or push.
Implemented in **judgement format 47**, with **6,341 tests passing**, **582 focused coverage
cases** and assertion-based witnesses for all **30 new behavior cases** across **16 rebuilt
isolated defects**, followed by restored controls and an explicit correct-source rebuild.
The [checkpoint handoff](../.v-path-risk-20261003/handoff.json) preserves source/build identities,
earlier failures, original evidence and the untouched production-test package.
The format-47 selected requester readback kept explicit requested/unavailable/no-recorded-question
states internal until consumer approval; the format-48 paged consumer is approved above, and no
public-surface gate was exempted.
Older judgement formats are refused by this branch rather than migrated or reinterpreted, while
the owner's frozen format-46 production-test application remains unchanged.
This is the saved qualification needed before SEC-071, not SEC-071 delivery or completed Stage 7.

**Owner-approved requester activation candidate and lab-first verification, 2026-10-02.**
Enable the existing shared GUI/CLI supported-question policy in the local candidate without
changing permission semantics, the three supported families, budgets, path compositions, rules
or screens; the separate legacy membership scan stays inactive.
The owner approved using the supplied copy at
`C:\Users\jistrand\source\repos\SecureAD.Next\next\artifacts\ad.lab-20261002-225337`
directly for the first real-capture check, rather than requiring another synthetic bundle or
another copy of this laboratory audit.
Preserve the existing judgement, manifest, summary and log before rejudging, hash-check the
sealed evidence and derivation, and retain earlier results and failed attempts.
The supplied audit records 8,418 objects and the domains `ad.lab`, `ba.ad.lab` and `ph.ad.lab`;
report what this capture demonstrates, not unverified cross-forest or production-scale coverage.
Synthetic verification remains necessary for precise edge cases and rebuilt deliberate defects.
The candidate must retain meaningful work and saved answers for each supported family, exact
source bindings, independent holder counts, explicit uncertainty, cancellation rollback and passive
reopening; a missing family is a verification gap, not a reason to manufacture a lab finding.
This is local candidate approval, not production readiness or permission to publish it: a later
production acceptance run and final activation decision remain separate, and no live access,
recapture, paused-campaign restart, optimization, new budget, UI change, commit or push is authorized.

**Separately approved requester-input reuse prerequisite, 2026-10-02.**
After the candidate exposed repeated capture verification in the existing source-reuse tests,
the owner approved carrying the existing protected capture reader and target lookup through
requester selection and all three proof families before the lab check.
Replace repeated opening/rebuilding in that branch without changing permission semantics,
source/generation checks, saved answers, counting or uncertainty; preserve the first failing
verification and exercise established combined questions with rebuilt isolated defects.
This bounded correction does not restart measurements, change processing limits, authorize
further optimization or waive the later production acceptance and activation decision.

**Owner-approved completion-message correction, 2026-10-02.**
The real lab candidate completed supported requester work while both hosts' existing wording
said membership questions were not scheduled; that sentence described a different, inactive scan.
The owner approved replacing only that message in CLI and GUI completion with:
"The separate Self-Membership scan was not run because no processing limit is configured.
Tier 0 requester checks have their own saved coverage; this does not mean nobody can add
themselves to a group."
This changes no layout, permission calculation, risk classification or scan, and does not
authorize repeating the completed lab judgement or implementing the broader risk-first presentation.

**Requester candidate checkpoint, 2026-10-02: implemented and real-lab verified, not production acceptance.**
The current unpublished candidate enables the shared supported-question policy in both hosts;
the old production-disabled statements below describe the earlier P-242 checkpoints, not this
local candidate.
The [verified handoff](../.v-requester-20261002/handoff.json) retains the source/build identities,
6,300-test pass, rebuilt defect checks, single lab invocation and unchanged original security
answers, including the first failures rather than replacing them with the later passes.
The lab's combined answers all use existing memberships; hypothetical new-membership combinations
remain synthetic verification, and the lab does not establish production resource requirements.
Peak memory was not obtained from this invocation, ordinary Add readiness remains separately
qualified, and neither completed supported questions nor a readable result constitutes all-path
coverage, a new SEC-071 finding or live takeover.
Representative production acceptance, final activation/release approval and the risk-first
presentation remain owed; no additional run, campaign, optimization, budget or publication follows
automatically from this checkpoint.

**Owner-approved RID 498 evidence check, 2026-10-02 (P-88).**
The owner approved comparing Enterprise Read-only Domain Controllers with protected and
unprotected controls and the AdminSDHolder template in the existing sealed lab audit, read-only.
The [captured comparison](../.v-lab-readback-20261003-011110/captured-protection-comparison.json)
corroborates the MS-ADTS reading that RID 498 is not automatically protected: its ordered permission
list matches Domain Users and inherits, while Domain Admins and RID 521 match AdminSDHolder and
block inheritance, in the captured Windows Server 2022 root-domain context.
This is one saved state, not observed SDProp execution, universal Windows-version proof, or a
decision about protection passed to members.
The subsequent **"ok make the correction"** approves only the bounded principal-claim correction:
RID 498 does not automatically confer AdminSDHolder protection, while independently established
membership protection still applies and its member-propagation claim remains unverified.
This supersedes only the RID 498 principal-protection position in `0089`, using the MS-ADTS
protected-set definition with the captured lab corroboration, not an assertion that Microsoft's
conflicting group-reference page was corrected or that every Windows version was observed.
Advance the protection catalogue version and retain saved older answers without reinterpretation;
do not change accepted owners, the authoritative Tier-0 definition, permission evaluation or screens.
Verification is synthetic/offline; original captures, frozen expectations and prior failures remain,
with no live testing, historical-bundle rederivation/rejudgement, publication, commit or push authorized.
The correction is implemented as protection catalogue **version 4** and offline verified with
**6,311 passing tests**, **120 focused coverage cases** and **15 new/updated behavior cases**
that detect nine isolated rebuilt defects, with correct sources explicitly rebuilt after restoration.
The [verified correction handoff](../.v-rid498-20261002/handoff.json) retains the initial fixture
failure, source/build identities and unchanged original evidence.
Existing version-3 derivations still carry their original disputed answer: applying this correction
to an older capture requires new derivation and judgement, not merely reopening it or using the
judgement-only discard action, and no original lab bundle was changed for this verification.

**Implementation checkpoint, 2026-10-02: the coordinated correction is offline-verified.**
The follow-up carries prepared statements and committed proof identities through later judging
transactions without allowing rolled-back identities to escape; selected saved paths retain an
explicit bounded, fingerprinted input projection, and completed-run permission classification
obtains only the descriptor identity it needs.
Dashboard reading runs off the UI thread and distinguishes loading, absent derivation and failed
saved membership; saved limitations retain every entry behind the approved 100-entry pages, and
local navigation diagnostics record build/run identity, opening, query, application and outcome.
A fresh Release rebuild and all 6,268 ordinary tests pass, and eight explicitly rebuilt isolated
defects are detected before the corrected isolated source is rebuilt and passes all controls.
The bounded fresh witness comparison preserves the exact selected answer, evidence seal,
generation, source binding, fixed targets, uncertainty, requester-family coverage and limitations;
its small-fixture timings are evidence about that fixture only, not a production speed claim.

**Production completion checkpoint, 2026-10-02.**
The owner's supplied `run6.log` is from the same `4deef9f` Release executable recorded in the
handoff and reaches terminal `CompletedDegraded` after proof writing and publication for 940,067
objects, with no logged warning or error and approximately 4 hours 42 minutes elapsed.
That establishes completed production judging, but the log does not establish that the result was
successfully reopened or browsed, and the follow-up source has not been run in production.
The original `SecureAD.Next` checkout remains at `4deef9f`; no live access, production retry,
application publication, commit or push occurred in the follow-up.

**Owner-approved discard-first rejudging, 2026-10-02.**
The owner has limited disk space and explicitly chose **"Discard judgement and judge again"**:
losing the existing judgement is acceptable during testing, so a whole-bundle copy or keeping both
old and new judgements must not be required by this action.
Reuse the same captured evidence and derived facts, preserve the run log, and discard only the
selected run's judgement before invoking the existing judging engine.
This is an explicit exception to retaining the previous judgement on cancellation: once discard
has succeeded, stopping or failing the new attempt leaves no completed judgement to open.
Do not present unfinished work as results, delete evidence or derived facts, access AD, or invoke
this action against the owner's production bundle from an implementation/verification session.
The owner approved the action in Home's existing analysis-action area for an already-judged run,
with one confirmation naming the run: **"This deletes this run's saved judgement before starting
again. Captured evidence, derived facts and the run log are kept. If judging is stopped or fails,
there will be no completed judgement to open."**
Use the existing judging progress and Stop control; ordinary Judge remains non-destructive.

**Owner-supplied running snippet, 2026-10-02:** the corrected source is
`C:\Users\jistrand\Downloads\new\run5.log`, preserved unchanged with its SHA-256 under
`.v-pipeline-61f8b32d/production-run5/`.
The logged executable SHA-256 matches the owner's local normal Release publish output and the
engine identifies `4deef9f`; the evidence seal and derivation generation match the earlier run.
The 940,067-object pass completes in 6,331,774 ms, scope selection in 453,488 ms and detailed
control assessment in 2,224,368 ms, including 1,974,764 ms in its storage step.
At the last supplied checkpoint, `2026-10-02T16:41:36Z`, ownership is still running with
2,315 of 7,225 targets completed and no path-writing, publication, failure or successful-finish
record; this is operational evidence, not a controlled comparison or a completed-run acceptance.

**Owner-approved follow-up trial, 2026-10-02: witness-grouped validation only.**
Within ownership/path source validation, prepare one resource's captured permissions once and check
all of its saved witnesses before discarding that preparation.
Preserve captured-owner and permission-entry checks, stored-edge proofs, original output order,
exact fingerprints, resource/source/generation binding, incomplete results and cancellation; do not
introduce a forest-wide permission cache, change analysis policy or activate requester discovery.
Approval includes focused regressions with explicitly rebuilt isolated defects and correct rebuilds,
complete saved-answer comparisons, and a fresh bounded before/after offline comparison of
repeated-witness and no-reuse cases, with a five-minute stop per invocation.
Do not automatically expand or repeat an inconclusive comparison; this tests the bounded change,
not production-scale acceptance.
Work only in the separate `p280-judging-followup` checkout while the owner tests `4deef9f`;
future publishing setup remains separate, with no production operation, UI change, commit or push.

**Witness-grouped trial outcome, 2026-10-02: isolated implementation verified, not adopted for
production.** All 849 directly related regression cases pass, and all 10 new checks detect their
intended explicitly rebuilt defects across five isolated variants before passing on correct rebuilds.
Both fresh before/after pairs agree across all 61 saved tables and all 603 objects' complete permission
answers, with exact source bindings, original occurrences and degraded results verified.
In the repeated-witness case, validation reads fall from 594 to 18, phase time from 909.3502 to
238.3459 ms and allocation from 297,692,496 to 18,781,936 bytes; complete judging plus reopening
changes from 5,410.7821 to 4,209.4049 ms.
The no-reuse case stays at 18 reads but is slower: validation 205.3262 to 248.8114 ms and complete
judging plus reopening 2,043.7705 to 2,661.5928 ms, with essentially unchanged allocation.
These are single fresh comparisons of small nine-domain synthetic fixtures, not representative
forest measurements or a universal speedup, and the slowdown remains an open finding rather than
being explained away or used to authorize more trials.
The [verification record](../.v-witness-a6d9712f/validation-summary.json) retains binaries, source
identities, input seals, failed attempts, comparisons and rebuilt controls.
The owner's original checkout remains clean at `4deef9f`; the follow-up stays uncommitted and
unpublished with no new production operation.

**Future normal Release publishing is prepared on the follow-up branch.**
`pwsh -File .\next\tools\Publish-Release.ps1` uses the existing GUI `FolderProfile`, includes the
current working sources, creates fresh output/build folders and records source and package hashes;
`-WhatIf` previews without building.
Eight isolated script checks detect eight deliberately broken script variants and pass with correct
scripts, including existing-output refusal, native failures, changed sources and dependency restoration.
No real application package or startup verification was performed in this follow-up.

**Earlier owner-approved priority, 2026-10-01: descriptor-first permission preparation and its
bounded offline validation, before further UI polish.** After the end-to-end design review, the owner
explicitly approved the first implementation scope below and requested a new-session handoff before
work starts. The goal is an audit that actually finishes in a realistic time, not just a faster object
counter; no numeric customer-runtime commitment has been agreed. Approval covers this bounded
implementation and validation on isolated offline inputs, not unrestricted optimization, new
measurement harnesses beyond the separately approved runner below, later-stage redesign, live
access or changes to the active production run.

### First redesign: approved scope and offline validation

**Status: approved small-fixture offline validation complete; not published or accepted at
production scale.**
**What was implemented versus what this continuation finished:** the main-pass application change
and its 31 new test cases were already in local WIP commit `8858a3a` before the VS Code handoff.
The VS Code continuation completed their outstanding review, verification and measurement without
another application-code edit; the benchmark compares the preserved old implementation with that
already-modified implementation, not the working files at the start and end of the VS Code session.
At that checkpoint later ownership/path stages still prepared inputs independently; the separately
approved input-reuse follow-up below is now offline verified, but the overall performance redesign
and production-scale acceptance are not complete.

The owner approved the defined scope with: *"Approve this implementation scope and its bounded
offline validation"* and subsequently said *"implement it"*; do not ask for that approval again.
The prior review-only restriction is lifted only for this scope. The fresh logging-corrected
before-control and current checkpoint are linked from [the work queue](PUNCH-LIST.md#current-bounded-correction).
**The owner approved resuming the same scope in VS Code, 2026-10-01, from current working files,
never by restoring a checkpoint over them.** That continuation completed implementation review,
all 31 new checks' deliberate-defect witnesses and a fresh Release rebuild with all 6,197 ordinary
offline cases passing. All six frozen before/after pairs agree across all 61 saved tables and every
object's complete permission answer, with their own seals, original occurrences, resource scope,
generation bindings and degraded outcomes verified; eight comparison controls also reject an
explicitly rebuilt implementation that compares nothing, then pass after a correct rebuild.
The [current checkpoint](../.v-dfirst-cb4a8c95/checkpoint-03/handoff.json) preserves the previous
checkpoints, interrupted attempts and exact measured binaries; no production or test source was
changed or restored during this continuation.

The [unchanged CPU benchmark comparison](../.v-dfirst-cb4a8c95/continuation-03-563b1149/benchmark-comparison.json)
records lab 12.820 → 9.875 seconds, shared 5.003 → 3.210 seconds, and distinct 6.527 → 7.094 seconds,
with allocation, memory, temporary/final storage, later phases and reopening retained for every
invocation. Repeated main-pass preparation is removed on these inputs, but the no-sharing slowdown
remains an open performance finding; these one-iteration synthetic/lab measurements do not establish
representative nine-domain performance, a customer-runtime ceiling or production readiness.
Further optimization or later-stage redesign needs a separate bounded approval, and this build must
not replace the owner's separately published diagnostic build; during that validation no application
publication, commit, push, live-forest access, production-run change, discovery activation or budget
change occurred.
Before the VS Code continuation, the owner authorized a **local work-in-progress commit** of the
accumulated source, tests and governing-document changes. That saved unfinished work, not an accepted
implementation; retained verification folders stay on disk outside Git, and that authorization did not include
pushing, publishing, restarting validation or changing the production run.

**New owner authorization, 2026-10-01: commit the completed checkpoint locally, then investigate and
propose bounded reuse of verified inputs through the currently active ownership/path-preparation
stages.** The local commit records the completed main-pass verification and its limits; retained
evidence and verification folders remain outside Git, and no push or publication is authorized.
That read-only investigation is complete. **The owner approved its bounded replacement and offline
validation on 2026-10-01: "approved lets implement it".** Reuse protected evidence and derivation
readers and their already-validated membership inputs within one judging attempt, then load finished
ownership records once for path preparation; never reuse pre-assessment status/counts as final.
Preserve source qualification and saved-witness checks, exact evidence/derivation/judgement binding,
resource scope, original occurrences, independent group-held counts, explicit incompleteness,
cancellation and file-handle lifetime. Keep reusable inputs privately owned; do not retain decoded
descriptors or extend classifier-index lifetimes across stages.

Approval includes focused regression checks with explicitly rebuilt isolated defects and correct
sources, complete saved-answer equivalence, and fresh control/candidate runs using unchanged
BenchmarkSuite7 and its frozen inputs/settings. Isolate short fresh TEMP/TMP before any test assembly
loading or discovery, retain exact binary provenance and failed attempts, and measure publication and
reopening as well as the earlier phases. This is not approval for extra measurement instrumentation,
UI changes, formats/migration, cross-run caches, parallel judging, requester activation, budgets,
live access, publication, production operations, another commit or push; customer-scale acceptance
and the no-sharing slowdown remain outstanding.

**Bounded input-reuse outcome, 2026-10-02: implemented and offline verified, not published.**
The attempt owns protected source readers and immutable membership inputs; path preparation shares
one finished ownership snapshot while retaining source qualification and saved-witness checks.
The selected derivation manifest is held only across final publication so it cannot change between
the last source check and selecting the new judgement. All 6,236 ordinary offline cases pass, and
all 39 new cases detect their intended explicitly rebuilt defects across 18 isolated variants before
passing on correct rebuilds. All six fresh control/candidate pairs agree across all 61 saved tables
and complete permission answers; comparison controls also reject a rebuilt empty comparison.

The [retained comparison](../.v-inputs-8f3a2c91/benchmark-comparison.json) records lab 15.417 to 9.239
seconds, shared 5.628 to 3.520, and distinct 10.889 to 6.758 on unchanged BenchmarkSuite7, with
fresh controls rather than the earlier descriptor-first timings. Lab path preparation is 5,390.8
to 3,004.8 ms and allocation 2,047.57 to 1,947.94 MiB; sampled working-set peaks fall on lab/shared
but rise from 109.28 to 110.28 MiB on distinct. There is substantial object-pass timing variation
too, so one configured iteration cannot attribute the whole elapsed difference to input reuse or
establish a repeatable percentage gain. Exact builds, source snapshots, every invocation, publication
and reopening, resource records, rebuilt defects and failed attempts are retained under
`.v-inputs-8f3a2c91/`; this does not fix the production path-proof memory failure below, establish
nine-domain viability, or authorize another correction, measurement campaign, publication or commit.

**Continuation approved, 2026-10-01; the separate production interruption remains an open investigation.**
The owner approved continuing and supplied `run3.log`, then clarified the observation: the Judge
button was clickable again in the morning, no error was visible, and completion was an assumption,
not an explicit success message. Do not ask for that observation again or record it as a successful
judgement. The preserved file ends with `WritingProofs completed=False`, before any publication or
successful-finish marker. The owner also supplied Windows report
`b033d7cb-c426-4bad-8692-47aa4d4b439e` and then its event XML: `AppHangTransient` was logged at
`2026-10-01T14:36:09.6863424Z`, 4 hours 8 minutes 17.6863424 seconds after the last judging record.
That is the reporting time, not a proven hang-start time; event-emitting PID 9104 does not identify
the hung application or contradict judging PID 4980. Three temporary attachments are listed, but
their availability has not been checked and neither process termination nor causation is established.
The timestamp question is answered and must not be asked again. Source review found a terminal-error
logging gap on the normal production route; **the owner approved the judging failure-logging correction
and offline checks, 2026-10-01**, prioritizing getting the logging right. Record failures/cancellation,
phase, attempt/generation and exception details without masking the original failure or changing
publication safeguards; this approval does not include UI changes, a production rerun or changes to
the frozen measurement runner. **The bounded logging correction is implemented and offline verified;
the rerun's executable hash, engine module identity and matching PDB source checksums now
confirm that it contains the validated logging correction, while the earlier failure's underlying cause
remains unknown.** The prepare-once approval remains intact, and the production log remains operational
evidence rather than the controlled baseline; [the work queue](PUNCH-LIST.md#current-bounded-correction)
records the retained observations and next proposed correction.

**Owner-supplied terminal rerun log, 2026-10-01:** `run4.log` reports attempt
`a7600b99-bcb7-419a-80d0-04c133869032` failing at `2026-10-02T03:00:13Z` with
`System.OutOfMemoryException` in JSON text conversion called by `Tier0PathStorage.Write`,
after 940,067 objects, during `WritingProofs`, with `publication=NotStarted` and cancellation false.
The executable SHA-256 and engine module identity match the previously verified logging-corrected
diagnostic build; this is not the in-progress input-reuse implementation, and an ended attempt is
not a completed judgement. Path preparation completed in 8,007,370 ms with requester selection
disabled; that operational observation is not a controlled comparison or a measurement of the
individual repeated reads. The preserved copy and hash are under
`.v-inputs-8f3a2c91/production-run4/`; the downloaded original was not changed.
The stack names JSON serialization but not an exact call site or allocation size: the whole-input
fingerprint's monolithic serialization is a concrete suspect, not a proven allocation-level cause.
Input reuse does not remove that operation and must not be described as fixing this failure;
the earlier run's unlogged failure is still not established to have the same cause.

**Owner-approved bounded memory correction, 2026-10-02:** replace only the shared path fingerprint
helper's whole-document JSON text/byte copies with streamed SHA-256 over exactly the same JSON bytes.
Keep serialization settings, ordering, fingerprint text, permission answers, source/generation
bindings and incomplete results unchanged; no format, graph, cache, processing-limit or UI change.
The owner approved the correction and bounded offline checks, including a small test-only stress
runner: compare with the existing algorithm, exercise at least 1 GiB of generated JSON under a
256 MiB managed-heap ceiling, verify its full digest and length, and demonstrate the allocation
failure in an explicitly rebuilt isolated old implementation.
That ceiling is a test safeguard, not a product budget; every new behavior check requires a rebuilt
defect witness and a correct rebuild, with short isolated TEMP/TMP set before test discovery.
Preserve the current verified input-reuse files and all earlier evidence.
This scope does not authorize a new end-to-end measurement campaign, production retry, publication,
commit or push; representative nine-domain judging completion, isolated result publication and
reopening still require separate authorization and remain the acceptance gate.

**Bounded fingerprint-memory outcome, 2026-10-02: implemented and offline verified, not production
acceptance.** All 6,250 ordinary offline tests pass; all 14 new checks detect their intended defects
across three explicitly rebuilt isolated variants and pass after correct rebuilds.
The approved stress check hashes 1,444,886,835 generated JSON bytes with the exact reference digest
under a 256 MiB managed-heap ceiling; the rebuilt old algorithm runs out of memory, and a rebuilt
dropped-byte variant is rejected rather than accepted merely for finishing.
Its 940,067 occurrences repeat nine synthetic relation templates, so this is a serialization-capacity
check, not a nine-domain forest-completion measurement.
The [retained verification](../.v-pathmem-13a79d2e/validation-summary.json) includes source/build
provenance, rebuilt controls and failed attempts; verified input reuse and earlier evidence remain
unchanged, and no live source was restored.
Loaded input graphs and individual large values still require memory, the exact allocation in
`run4.log` remains unproven, and representative judging completion/publication/readback remain
unaccepted and separately gated, with no production retry, publication, commit or push.

**Owner authorization, 2026-10-02: publish the normal Release GUI application.** After confirming
that the existing `FolderProfile` includes the current uncommitted input-reuse and memory corrections,
the owner said *"ok publish it"*.
Use the existing Windows x64, self-contained, single-file profile and preserve older packages by
publishing into a fresh output folder; retain exact source and package identity.
This authorizes local application packaging and its verification, not a new judging attempt,
judgement-result publication, production access, recapture, measurement campaign, commit or push.

**Owner follow-up, 2026-10-02: commit locally; the owner will publish in Visual Studio.**
The owner stopped agent packaging and authorized committing the verified current source, tests and
governing documents so he can publish his normal Release build without further packaging work here.
No publish command had run; retained verification/evidence folders stay outside Git, and no push or
agent-run judging retry is authorized.

**Additional production observations, supplied with that approval:** Home shows capture `Finished`
and analysis `Facts derived — not judged`, while Dashboard says `Group membership has not been
worked out yet` and that deriving has not run. The owner reports unusably slow screen changes and
Assets spending minutes loading before withholding a saved result for a source/generation mismatch
or a generation change during reading. Source review confirmed that Dashboard currently maps a failed
membership read to the same state as no derivation; that reporting defect remains unfixed, and the
Assets refusal/loading cause is still unconfirmed. Do not equate a stored derivation with a successfully
verified reading, weaken the refusal, change screen wording without approval, or substitute stale/empty
results to make the screens agree.

**Readback investigation follow-up:** the source retains unfinished judgement markers after a failed
attempt, and the screen reader treats a pending judgement as a blocker even when reading derived
facts; its captured-data validity check can also reject the read for that pending state. **The owner's
pre-rerun inventory confirmed both `judgement.db.partial` and `judgement.current.json.partial`,
with no published judgement manifest/database listed.** The recorded derivation was selected as
`ce5b7114-14af-44da-95d7-acdca87a9015`, matching the judging log; its database and seal are present.
The declared evidence seal also matches that log, but database bytes have not been rehashed. The
pending files are sufficient to trigger the observed refusal path; their empty pending generation ID
is the normal start-of-attempt marker, not something to repair manually. That historical inventory gave
18.67 GiB of evidence, 2.84 GiB of derived facts, 12.42 GiB of failed judgement and 48.04 GiB free;
it is not current capacity, a replay guarantee or evidence of free space when the failure occurred.
Preserve failed output deliberately: starting another judgement replaces its staging database.
**Owner clarification, 2026-10-01:** the owner wants to use the normal Release publish to obtain the
better log, not wait for screen fixes or a special CLI package, and does not have space to duplicate
the whole captured run. The normal GUI uses the corrected judging engine; a separate CLI package is
optional, not a requirement. Begin investigation with a read-only file inventory, free-space reading,
small current/pending manifests and seals, and the already supplied log; do not require database copies
for that metadata check. This cannot recover an exception that was never logged. Any replay still
replaces the failed staging database and needs space for new results, so decide explicitly what failed
output to retain before overwriting it; lack of space is not permission to delete evidence or clear
markers to bypass a refusal. No agent publication or replay has occurred, and this diagnostic priority
does not accept the screen defects as fixed or establish production readiness.
**Owner update, 2026-10-01: the new judgement is already running.** The owner reports deleting the
partial judgement for space while doing other concurrent work unknown to the assistant; the exact
deletion timing relative to the new attempt was not stated. The proposed archive plan is superseded,
not a reason to stop the run, recreate the removed file or seek retroactive approval. Keep the active
attempt's files untouched, use actual current free space, and retain
the resulting log; the earlier log/inventory remain available but the removed database cannot be
assumed available for post-mortem reading. Do not treat this shared-machine diagnostic run as a
controlled performance comparison, or assume exclusive access to the owner's disk or other work.
**Verified rerun checkpoint:** attempt `a7600b99-bcb7-419a-80d0-04c133869032` produces generation
`d82215e2-0d2d-4af7-8b4d-a7f933d76db5` against the same evidence seal and derivation generation as
the previous attempt. The supplied excerpt reaches 475,499 objects at `2026-10-01T20:57:36Z`, still
in the object pass, with no terminal failure or publication shown; this is progress, not a completion
forecast or proof that the later failing stage is repaired. Build/source verification and the checkpoint
are retained alongside the previous log under `next/artifacts/production-run3-review-20261001-b03b6a84/`.

**The unit of preparation is the captured descriptor, not each object carrying it.** During the main
judging pass, decode the original descriptor bytes, retain capture/re-parsing errors and completeness,
classify and validate its entries, and calculate its saved fingerprints once within the exact evidence,
catalogue/parser/producer and analysis context. Hold an immutable prepared result; a repeated numeric
descriptor ID supplied by a caller is never sufficient proof that reuse is valid. Process descriptor
groups explicitly and stream their objects, rather than retaining the decoded forest or materializing
an entire object's group in memory; ordering and temporary preparation costs belong in the measurement.

**Object-specific work stays object-specific.** Every applicable object still reaches the existing
rules, LAPS inventory and Tier-0 observation. Its identity, captured readability, SELF presentation,
resource scope and requester authorization must not be inferred from another object's shared result.
Grouping must preserve existing name-ambiguity behavior, logical answers and counting semantics;
group-held permission counts remain independent of member/route counts. Write each descriptor's
classifications once and retain every required object link, with pending identities trusted only in
their transaction and promoted after commit or discarded on rollback.

**Boundaries.** Preserve the saved format and completed-run reading contract, all original entry
occurrences/ordinals/order/raw masks/application data, per-right meanings and reasons, inheritance and
captured-schema support, and exact object/source/generation binding. Do not substitute canonicalized
permissions, change rules or the authoritative Tier-0 definition, enable requester discovery, choose
new production limits, introduce cross-run caches, migration or legacy readers, or combine this with
binary encoding, a database replacement or parallel execution. Replace repeated main-pass preparation
without permanent competing implementations or an unchecked fast path. Protected input reuse through
later ownership/path stages is covered by the separately approved follow-up above; neither change
claims to make every later permission read occur once.

**Offline validation is part of the approval, under these conditions:**

- Before production edits, preserve the current uncommitted source and establish a measured baseline
  with an existing suitable artifact that exercises the changed paths; use exact executable hashes
  and module identities, not a Git revision alone. Any new measurement harness or extension still
  requires separate approval. Freeze the measurement artifact and rerun the same workload after the
  change, with identical evidence, derivation, rules, evaluation time, feature policy, runtime and
  hardware; never treat the other machine's live log as a controlled before/after baseline.
- **Separate measurement approval, 2026-10-01:** the owner approved *"the isolated measurement
  runner and bounded offline baseline"*. Add a separate retained-output runner for the current
  `JudgingRun.JudgeAudit` policy, initially covering shared/distinct synthetic descriptors and the
  verified saved laboratory input, without changing the historical runners or their execution
  guards. Isolate temporary files before assembly loading, identify the exact measured binaries,
  keep requester discovery disabled and freeze the new runner after its first successful run;
  this does not authorize live access, production-scale readiness claims or broader measurement
  campaigns, and the remaining boundaries below still apply.
- Use fresh isolated copies of sealed evidence and matching derivation, never the active run or
  originals. Set TEMP/TMP before any test discovery or assembly loading. Retain failed attempts,
  outliers, frozen evidence, historical measurements and subsequent uncommitted work; do not delete
  originals, recapture, access a live forest, publish a package, commit or push.
- Cover shared and distinct descriptors, SELF/owner/cross-domain cases, duplicate entries and
  ordinal gaps, raw generic masks, inheritance, unsupported entries, missing/unreadable/malformed/
  partial/null/empty DACLs, context isolation, reordered object processing, cancellation and rollback.
  Prepared data must resist caller mutation and cannot be reused under a different bound context.
- Independently test all three bindings in `docs/specs/P280-JUDGEMENT-OCCURRENCE-ROWS.md`:
  evidence object-to-descriptor, descriptor/ordinal-to-entry, and entry-to-saved-interpretation.
  Corrupted associations must be refused, including wrong descriptors with equal counts and
  substituted otherwise-valid readings. Keep frozen hashes and Microsoft-anchored expectations;
  needing to edit a golden value is a stop-and-review finding, not a test repair.
- Mutation-test every new behavior check, explicitly rebuilding both the deliberately broken and
  restored code. Compare saved logical fields and outcomes, not only aggregate counts; preserve
  degraded/unknown answers rather than forcing success, and verify each result's own seals and
  bindings even where generation identifiers or storage row ordering legitimately differ.
- Validate focused synthetic cases, then lab integration, then representative nine-domain
  production-scale evidence. A small or sharing-heavy synthetic capture cannot establish production
  runtime, memory limits or readiness. Record actual descriptor preparation/classification counts,
  preparation and object-pass timings, later phases, publication, reopening, peak memory and
  temporary/final disk use; record cancellation and preserve the previously published generation.
- Acceptance requires demonstrated removal of repeated preparation, reproducible runtime benefit
  with resource trade-offs reported, unchanged security answers and successful publication/reopening.
  Moving time into preparation or later stages is not an end-to-end gain. If occurrence-row writes
  remain dominant, stop at the approved boundary and propose storage work separately; do not expand
  this implementation or declare customer readiness without an agreed end-to-end runtime ceiling.

The preservation snapshot is `next/artifacts/descriptor-first-handoff-20261001-7a23c981/`; its manifest
records source state, copied supplied logs and the unchanged published GUI. It is not a measured
baseline and must never be automatically restored over later work. P-191 remains implemented and
offline verified in `.v-p191-0e09e3d1/`; the owner has begun a lab review but has not yet reported
physical display or packaged-UI acceptance.

**Previously approved bounded UI work, 2026-10-01: the Findings-screen pass (P-191).**
While the existing production judgement runs, keep the findings list, add **Close details**, correct
explanation contrast, and separate the existing **Why it matters**, **What to do**, and **What this
rule looks for** sections. Verify navigation, filtering, selection and dismissal offline, with normal
laptop/external-monitor checks remaining explicit if unperformed; preserve the running job, published
package, evidence and prior uncommitted work. That approval moved this bounded presentation session
ahead of further Stage 7 work, not a general UI redesign, rule expansion, reports, performance work,
live access, publication, commit or push.

**The next feature remains Stage 7 — paths to Tier 0, behind the performance-first priority above.** The bounded correctness pass **P-41,
P-136, P-162, P-173** is implemented and offline verified, as recorded in
[the work queue](PUNCH-LIST.md#agreed-next-work); P-136's reported case was already guarded and
received regression coverage rather than a production change. Do not replace the next feature with
general capture cleanup or require the punch list to be empty; retain validated, self-contained
checkpoints and the existing stop rules for false security claims, evidence loss and invalid verification.

The remaining P-216 caller-status gap, nonblocking presentation/readback work, standalone rule and
inventory additions, and speculative performance tuning are deferred as listed in
[the work queue](PUNCH-LIST.md#deferred-from-the-next-pass). P-217 gates deletion of valuable evidence;
P-157 must be addressed before relying on the affected LAPS results, without automatically blocking all
path development. P-93 remains a Stage 10 acceptance-lifecycle question and P-96 waits for actual path
results; production requester acceptance and wider supported paths remain Stage 7 work, while
P-143 declarations are deferred until after main feature/rule delivery under the 2026-10-03 decision.
P-142's bounded enterprise CA classification is implemented and offline verified.
This order does not accept unperformed laboratory, customer-scale or display checks, authorize new
live access, or waive the normal approval of concrete product and UI changes.

**What the product is for, and what it is not for — the owner, 2026-09-22.** The focus is **control
edges, the rules, and pathing to Tier 0**. Reading an individual object's permissions is not where
users spend their time; most of the time nobody will open that screen. Performance work therefore
belongs on **judging**, and specifically on the object interval where 98.6% of the added elapsed
cost sits — not on making saved results pleasanter to browse.

**The consequence, applied the same day.** The bounded paging reader and the Permissions-screen
paging were cut from P-249 rather than built, and the work retained at
`next/artifacts/p249-final-b/continuation-06/reverted/`. The trial's own evidence agreed with the
owner before he was asked: `run-1-a/reader-3.json` measured the largest object in the laboratory
capture at 79 entries, materialised whole in 4.25 ms using 1.1 MB, with the other sampled extremes
at 2.23–3.43 ms. A screen change costing an owner approval and a session of work, to save four
milliseconds on a screen nobody opens, is the wrong target however well it is built.

**One premise of that paragraph was wrong by thirty times, corrected 2026-09-24.** It said the
production forest averages about 17 access control entries per object against the laboratory's 25,
and concluded production objects are *smaller* on average. **They are not.**
`--judgement-forecast` measured `ad.ssa.gov-20260924-020431` directly: **330,856,576 permission
occurrences across 659,196 objects carrying readable permissions is 502 entries per object**, and
the descriptors themselves average 521. The owner confirmed the 17 was wrong and believes it was a
laboratory figure that got attached to the wrong forest.

**The decision to cut paging still stands, on its other ground.** Performance work belongs on
judging because that is where the cost is, and `P-280` has since measured exactly how much — a
production judgement would be 136.5 GiB, of which 72% is one name copied three times. That argument
never needed the 17. But the *reason* given for it — that production objects are small — is deleted
rather than repaired, and **nothing may be designed on the belief that an object carries a couple
of dozen entries.** If paging is ever reconsidered, it must be against 502.

**Owner-approved rule-path correction, 2026-09-27:** implement reuse of membership traversal inputs
within one verified derivation reader, indexed protected-principal lookup, and reuse of the current
object's permission reading across its rules, with correctness testing but no new performance
campaign. The owner subsequently approved one quick bounded before/after measurement using existing
offline inputs, not repeated trials or a profiler session; an inconclusive result is reported rather
than used to start more measurements automatically. Preserve security answers, uncertainty, domain scope and generation
binding; this does not authorize changing the running production job, the pending logging work,
analysis budgets, publishing, committing or pushing. The supplied first-100,000-object checkpoint
attributes 24,016,043 of 24,951,583 milliseconds to rules; it does not measure the later hours or
establish a speedup for these corrections.

**Owner-approved logging and carry-build follow-up, 2026-09-27:** replace callback-dependent logging
with independent one-minute status in both CLI and UI judging, including the current rule/operation,
completed-object count and elapsed activity, and five-minute per-rule detail including a rule that
has not returned. Validate no-callback and shutdown behavior, then publish new self-contained CLI/UI
packages containing the rule-path improvements without overwriting prior packages or touching the
running production job; no further benchmark campaign, commit or push is authorized.

**Owner-approved permission-storage follow-up:** implement the reviewed identity-only classification
write, same-instance equality shortcut, mutation-safe reuse of schema serialization, and a single
per-descriptor occurrence-count pass with link-integrity checks; validate correctness and provide
fresh self-contained CLI/UI packages for owner-run production testing. Preserve existing proof
formats, every permission occurrence, incomplete results and transaction behavior; no running-job
interference, additional benchmark campaign, commit or push is authorized. Broader membership,
trustee-resolution and later control/path optimizations remain outside this bounded change.

**Owner-approved first post-object correction:** remove the redundant full SID-index search after
an exact missing non-BUILTIN lookup, skip empty requester enrichment without skipping baseline paths
or phase notifications, and avoid loading ownership targets before an already-planned scope branch.
Validate exact identity/ambiguity, fallback names, unresolved witnesses, nonempty requester behavior
and cancellation, then provide a separately named self-contained CLI/UI package; preserve the
current production run and old packages. Witness-grouped validation and broader representation/cache
changes are separate follow-ups; this scope authorizes no benchmark campaign, cleanup, commit or push.

**Owner-approved quick post-object measurement, 2026-09-28:** compare the published
`carry-storage-497ca6b5` and `carry-postpass-0290f7e7` CLI packages once each on separate copies of
the same sealed lab input, with a two-minute limit per run and retained binary/input identities,
logs and outcomes. This narrow follow-up authorizes no profiler, repeated campaign, new measurement
harness, optimization, production access, cleanup, commit or push; a lab result is not a production
runtime forecast.

**Owner-approved bounded post-pass lookup correction and offline runner, 2026-09-29:** reuse the
existing reader-local object-identity lookup before the first admitted target's evidence read and
make stored candidate-edge parent lookup use its existing key while retaining exact target matching.
The owner separately approved a new offline measurement runner because the existing judging
benchmarks bypass discovery-gated admission: use a fixed forest-sized synthetic lookup population
and fresh copies of retained sealed lab input, establish a baseline before either production change,
then compare the same workload and mutation-verify the new behavior checks.
Preserve permission proof, counting, ambiguity, incompleteness, generation binding, all prior work,
original evidence, packages and failed attempts; isolate temporary directories before test loading.
Stop on an unexpected measurement failure rather than repeating a campaign automatically; this
approval does not authorize live access, production interruption, new budgets, UI changes,
publishing, cleanup, commits or pushes, or establish the running production executable's identity.

**Owner-approved bounded post-pass diagnostics and a separate validation package, 2026-09-29:**
add run-log timings for candidate resolution, scope selection, admitted permission-proof reading,
evaluation and storage, ownership assessment and completion checks, with distinct execution/traversal
counters, process-memory snapshots and executable/engine identity.
These are diagnostics, not security-completeness claims or UI changes; validate offline and produce
a separately named CLI/UI package without replacing existing packages or disturbing the running audit.
Preserve uncommitted work, sealed evidence, prior measurements, failed attempts and historical tests;
isolate temporary storage before test discovery and rebuild deliberate defects and restored code.
A representative full-sized offline run remains a separate approval: no live forest access,
production interruption, recapture, new budgets, cleanup, commit or push is authorized here.

**Owner-approved correctness follow-up after repository recovery:** finish the required-argument
and architecture-check repairs, retain portable-summary read failures, and complete the existing
diagnostics verification before producing separate CLI/UI validation packages.
Keep the existing summary presentation and error vocabulary; distinguish run completion from evidence
coverage rather than introducing a blanket completion flag or exempting the summary from checks.
Use synthetic/offline verification, rebuild deliberate defects and restored sources, and preserve
prior work, evidence, measurement records and failed attempts.
Package startup checks must not change the operator's settings or browse the original library merely
to obtain a passing check; record unperformed UI and display checks as outstanding, not accepted.
This continuation authorizes no live access, new performance campaign, production-sized replay,
production budget or discovery change, cleanup, commit or push.

**Owner-approved follow-on order: finish Stage 7, then reconcile the reviewed replacement rule
specifications and implement the remaining rule coverage; reaffirmed 2026-10-03 with P-143 deferred.** The review and its retained source set are
recorded as P-235–P-239 in [the work queue](PUNCH-LIST.md#rule-specification-review--after-stage-7).
The proposed handoff is a basis for later bounded implementation, not blanket approval of its severities,
thresholds, collection extensions, compatibility requirements or screen changes; inventory/correlation
dispositions must not become duplicate scheduled rules merely to reproduce the predecessor's rule count.
Stage 7's own requester coverage, supported path compositions, SEC-071 findings and presentation remain
Stage 7 work, not postponed to that later rule pass. Existing safety stops and outstanding acceptance,
including the published CI failure recorded under P-227, remain explicit rather than accepted by this order.

**Owner requirement for Stage 7 completion: automatic normal audits, not separate manual path tools.**
A normal GUI or CLI audit must select the relevant account questions from captured evidence, run the
Stage 7 analysis, and save its findings, routes and coverage without an administrator-maintained
requester list or a separate per-object analysis step. This completion requirement covers the remaining
Stage 7 scope, not merely automatic execution of the three currently supported requester families;
SEC-071 findings, broader approved compositions and run-wide presentation/counts remain required.
P-143 declarations remain owed but were explicitly deferred beyond this milestone on 2026-10-03.
Screens read and validate saved results rather than starting new analysis, and missing
evidence, unsupported analysis and failed or unfinished work remain explicit rather than becoming safe
answers. Automatic analysis does not authorize changes to AD; the existing separate approval boundaries
for production activation, budgets and paused measurements still apply.

**Stage 7 completion clarification, 2026-10-02:** the successful requester-enabled packaged GUI
lab audit verifies the three existing supported families, not the full Stage 7 requirement above.
The approved SEC-071 checkpoint now provides findings and risk-first saved readback for the three
current qualified families, including whole-run counts.
Remaining approved path combinations and distance/tier summaries, with their corresponding findings
and presentation, are still unfinished; the owner confirmed on 2026-10-03 that these must be completed
before closing Stage 7 rather than deferred with P-143.
Representative production execution/readback acceptance remains outstanding separately.
General finding tuning must not replace this work, but deciding which paths represent actual risk
rather than expected administration is part of delivering Stage 7's own findings, not something that
can all be deferred until after Stage 7 is called complete.

**Earlier owner-selected Stage 7 priority: production requester coverage**, before broader path
compositions, P-143 declarations, SEC-071 findings and path presentation. Start from checkpoint 7's
offline permission-led selector and checkpoint 8's shared targets, and prepare a bounded proposal
for normal GUI/CLI account selection, execution and coverage accounting, including the representative
measurements and activation decisions needed for approval. This priority is not authorization for
new implementation, requester activation, budgets, screen changes, live access, optimization or new
measurement-harness code, commit or push; it does not reopen the rule-catalogue review or require an
administrator-maintained requester list.

**Separately owner-approved measurement scope, for a later session only:** preservation-safe offline
measurement of the three supported requester families, including minimal runner code, using isolated
sealed-evidence copies and retained synthetic workloads at the documented nine-domain forest scale.
Record exact source/build and evidence-generation provenance, verify that each family actually does
work, vary relevant-group/member density, and measure selection, each proof family, storage, reopening,
memory and cancellation response without changing originals or frozen historical artifacts. This is
scope approval, not authorization to start during preparation; the subsequent implementation approval
below authorizes starting this work, while production activation, numerical budgets, screen changes, optimization, live access, recapture,
commit and push still require separate authorization.

**Owner-approved implementation: shared GUI/CLI requester coverage.** The subsequent request
"approved lets implement it" authorizes the proposed integration and approved offline measurement work.
Both hosts use one explicit selection policy, disabled in production pending activation approval, for
the same three checkpoint-7 families and checkpoint-8 shared targets without widening authorization.
Read coverage from saved selection sources and proof batches, reconcile question identities before
publication, and keep missing inputs, unsupported analysis, unresolved identities and unrequested work
distinct; empty or completed supported scans never establish safety or forest-wide coverage.
Failed, cancelled and unfinished attempts remain separate from the previous valid generation, with
passive reopening and independent group-held permission counts preserved. Verification includes both
hosts, rebuilt deliberate-defect checks, focused coverage, the full offline suite and the approved
measurements; activation is a subsequent explicit decision, not an unrelated backlog prerequisite.
No screen changes, numerical budgets, broader path compositions, optimization, live access, recapture,
commit or push are authorized; P-227, P-240 verification and P-241 remain independently open.

**P-242: integration implemented and offline verified; measurements paused and unfinished.** The full
offline suite passes 5,432 cases and focused coverage passes all 42 new cases, with rebuilt
deliberate-defect witnesses and an additional check that the coverage verdict cannot claim unrequested
or unavailable work completed. The failed first full run, unchanged historical records and hash-checked
source-snapshot archive are retained with the qualified implementation handoff at
`next/artifacts/stage7-requester-integration-validation/6c4fc88314a14c2788580ed29d93f5c5/implementation-summary.json`;
this is not production activation, completed Stage 7, measurement acceptance or closure of P-227,
P-240 verification or P-241.

The preservation-safe runner is now offline verified with 5,444 full-suite cases and 54 focused
coverage cases, including 12 runner checks with rebuilt deliberate-defect witnesses. Initial
measurements and retained failures are qualified in
`next/artifacts/p242-measurement/d48f66126b064a9f8157fe1a1a79f6f0/measurement-handoff.json`;
the small synthetic workload executes all three families, including post-membership authorization,
but its combined authorization answers remain Unknown rather than established routes. The retained
lab capture uses evidence version 10 while this build reads version 12; it was not migrated or
recaptured. Nine-domain volume/density results and separate established combined-authorization
workloads remain outstanding, not customer-scale acceptance or grounds for activation or budgets.

**Owner-directed return to ordinary Stage 7 development:** measurements are paused, not accepted or
permanently cancelled; do not resume them, investigate the stopped process, optimize, or activate
requester discovery by interpreting "continue" as authorization. The first nine-domain volume input
was generated and independently verified, but its measurement stopped without a completed result;
the other two variants never started, and the termination cause remains unproven. Retain all inputs,
partial databases, WAL files, failures, diagnostics and historical source-snapshot mappings unchanged;
older launch records do not establish current liveness. P-242 plan steps 1–8 remain complete,
step 9 unfinished and step 10 pending. Reconcile the remaining Stage 7 requirements and propose one
small non-measurement feature for explicit scope and UI approval before implementation, without
reopening the approved P-242 integration or treating Stage 7 as complete.

**Owner-approved reduced offline pilot, authorized to start by "ok lets do it":** generate a separate
synthetic input of 34,700 objects, 590,000 physical permission entries and nine domains using the
existing configurable workload generator and preservation-safe runner. Retain meaningful membership
density and route scenarios across all three requester families, checking actual work and distinguishing
established from unresolved answers rather than accepting empty or uniformly unresolved work as proof
of readiness. Record input/build provenance, elapsed work, memory, storage/readback and cancellation
evidence in fresh output; keep original large inputs, partial databases, failures and historical
source snapshots/mappings untouched. These figures define a pilot input, not a production budget;
do not assume linear scaling or treat a pilot pass as full-forest acceptance. Only this reduced pilot
resumes: the unfinished full-volume series and stopped-process investigation are not restarted,
P-242 step 9 remains unfinished and step 10 pending, and production requester selection remains Disabled
with the legacy discovery budget null. Optimization, new measurement-harness code, production activation,
new budgets, live AD access, recapture, migration, deletion, commit and push require separate approval.

**The reduced pilot's first preflight was blocked by the original synthetic scenarios, not by a renewed pause.**
The selected density is 18 relevant group sets with four members per holder, taken from the retained
workload design: two sets per domain exercise both Self-Membership and Write Members, with 90 stored
membership values; this is a synthetic experiment, not reconstructed customer membership.
The original generator placed each requester's existing holder permission before the obtained group's permission
on the same Tier-0 target, so the combined proof cannot attribute that first grant to the group being
joined and remains Unknown regardless of these size/density inputs.
At that preflight the generator, runner and two relevant evaluators matched the archived source hashes; the retained smoke
has four established direct-requester answers, four established own-account membership answers and zero
established combined answers, and is not new scale evidence.
The no-launch record is `next/artifacts/p242-reduced-pilot/0869cdf29da34de7b5217a3091078319/preflight-blocked.json`;
no reduced input or timing, memory, storage/readback or cancellation measurement was produced in that attempt.
A bounded generator-only extension to separate established combined-route scenarios while retaining
unresolved scenarios is now explicitly approved: "Approve the generator-only scenario extension,
verify it offline, then execute the reduced pilot"; production proof checks must remain unchanged.
The extension adds an opt-in separate synthetic target using the existing fixed Tier-0 definition,
retaining the original target and six-argument generator mode, followed by focused rebuilt
deliberate-defect verification and execution of the already-approved reduced shape.
The current durable authorization is `next/artifacts/p242-reduced-pilot/35f8f6fe210b4689af59c03ced79b9ef/authorization.json`.
The reduced execution approval remains in force with this bounded generator change;
P-242 steps 1–8 remain complete, step 9 unfinished and step 10 pending, with all other boundaries unchanged.

The opt-in extension is implemented and the final Release build passes all 20 focused checks,
including eight new checks witnessed by four rebuilt deliberate-defect variants; the historical full
suite was not repeated and these checks are not scale evidence.
**The reduced pilot and its separate cancellation observation have now completed successfully.**
The independently verified input contains 34,700 objects, 590,000 physical ACEs, nine domains,
90 member values and mean DN length 96.97683; both runs used the same archived Release executable
and separate copies of the same sealed evidence, with original inputs unchanged.
The main process took 24 min 21.551 sec including preparation and validation: requester-enabled
judging took 9 min 7.249 sec, combined proofs 1 min 43.480 sec, and passive reopening/validation
8 min 29.817 sec; peak process working set was 602.984 MiB and the saved judgement was 96.488 MiB.
There are 72 established requester-permission answers, 72 established own-account membership answers,
and 144 combined answers split into 72 Established and 72 Unknown; each membership-permission type
has 36 established and 36 unresolved combined answers, not an all-Unknown substitute for readiness.
All 576 saved/nested proof identity checks matched the evidence and generations, and all 90 counted
group-held permission rows, including supports and uncertainty, match the requester-disabled judgement.
Cancellation was requested 1,035.861 ms into combined-proof work after 81,687,496 managed bytes had
been allocated, and responded in 61.576 ms; this single observation includes unwinding/runner overhead
and is not a guaranteed response bound or processing budget.
That process exited successfully after 19 min 17.927 sec, retaining and passively reopening its previous
valid requester-disabled generation as NotRequested, not publishing an empty successful requester result.
The final handoff and preservation qualifications are retained at
`next/artifacts/p242-reduced-pilot/35f8f6fe210b4689af59c03ced79b9ef/handoff-d0cd092921394478a703aea153763ead/handoff.json`;
earlier launch/progress, failures and incomplete summaries remain historical records, not current liveness.
These timings isolate the shared JudgeAudit path with no scheduled rules, not total normal-audit/UI
runtime; synthetic density is not reconstructed customer membership and no linear extrapolation or
full-forest acceptance follows. Preparation and validated readback costs remain material measured
readiness concerns, not authorization to optimize, weaken proof/readback checks, set budgets or activate
production; P-242 steps 1–8 remain complete, step 9 unfinished and step 10 pending, with full-volume
measurements and the stopped-process investigation still paused and independent open checks unchanged.

**Owner-approved read-only follow-up:** "yes" authorized investigation of preparation and saved-result
validation using retained pilot records and current source, with no new measurements or optimization.
That investigation is complete; its source/data/query-plan findings and bounded proposal are retained in
`next/artifacts/p242-reduced-pilot/35f8f6fe210b4689af59c03ced79b9ef/read-only-review-b614d80e6eeb4bc7b6262f6acfef0aab/findings.json`.
The approved change is an opened-reader, bulk-validation identity lookup that avoids repeated
name scans while retaining every uncertainty witness and proof check; it must preserve SQLite's
name ambiguity/case rules, exact generations and passive readback without changing sealed evidence.
This uses extra temporary memory; at approval, neither its speedup nor the exact share of phase time
spent in name scans had been measured. The owner explicitly approved "the lookup-only optimization,
offline verification, and unchanged reduced-pilot repeat": use the identical sealed input and unchanged
main/cancellation runner modes in fresh outputs, with focused rebuilt deliberate-defect checks before measurement.
Authorization and preserved pre-existing work are recorded under
`next/artifacts/p242-lookup-optimization/75b787807339426eb8a5023a4ad85154/authorization.json`; no permission
evaluator, evidence schema, production policy, budget, full-volume or live-access change is included.

**Lookup-only optimization implemented and reduced repeat completed, with regressions retained.**
All 541 focused reader/path/runner checks pass, and all nine new checks detect rebuilt deliberate
defects across four variants; the case-comparison variant produced two valid failures rather than the
one initially expected, and its failed validation record is retained without weakening either check.
The unchanged runner used fresh copies of the exact original sealed 34,700-object input, not a
regenerated workload: main elapsed fell from 1,461.551 to 698.654 seconds, selected judging from
547.249 to 160.368 seconds, and selected path preparation from 388.429 to 14.105 seconds.
Validated reopening fell only from 509.817 to 459.105 seconds and remains a material readiness concern;
peak process working set increased from 602.984 to 638.754 MiB and reopening managed allocations
increased slightly, so this is not an across-the-board resource improvement.
The saved judgement remains 101,175,296 bytes, with identical normalized saved questions/proofs,
original ACE supports, 90 independent permission rows, 34,700 uncertainty records, 34,701 path outcomes
and 27 anchors; exact after-run generation binding and passive readback were verified separately.
Cancellation preserved and reopened the previous valid NotRequested generation, but its observed
response worsened from 61.576 to 980.318 ms and the nominal 1,000 ms request fired at 2,306.459 ms.
Independent read-only comparison work overlapped that cancellation run, so attribution to the code
change is unproven; the result remains visible rather than selectively rerun or accepted as a bound.
The paired results, unchanged-input/build provenance, retained defects and preservation review are in
`next/artifacts/p242-lookup-optimization/75b787807339426eb8a5023a4ad85154/handoff.json`.
This is one reduced synthetic pair with no scheduled rules, not full normal-audit/UI timing, full-forest
acceptance, a processing budget or production activation; further optimization or additional measurement
requires approval, and P-242 steps 1–8 remain complete, step 9 unfinished and step 10 pending.

**Owner-approved correctness pass — implemented and offline verified as P-243–P-245:**
"begin correction of these defects" authorizes correcting
member-schema name substitution, premature distribution-group exclusion of captured requester SID
history, and saved-path permission-ID/display-cursor confusion, including affected shared consumers.
Use synthetic offline regressions, rebuilt deliberate-defect checks, coverage and full-suite validation;
preserve original evidence and failed records, exact generations, uncertainty and independent counts.
This does not authorize efficiency changes, new measurements, UI wording/layout changes, requester
activation, budgets, live access, migration, recapture, deletion, commit or push; P-242 steps stay unchanged.

The restored solution build and all **5,552 offline tests** pass; all **26 new regression cases** pass
under coverage collection and detect deliberate defects across **10 accepted rebuilt variants**.
Original failures and the superseded display-test witness remain retained, with the final verification
and preservation record at `next/artifacts/stage7-correctness-validation/7a145e4d584d44f8b9b27331c3f81ea9/handoff.json`.
This does not complete Stage 7 or P-242 readiness, close P-227/P-240 verification/P-241, accept unperformed
physical-display checks, or activate requester selection; the production policy remains Disabled and
the legacy discovery budget remains null.

**Owner-approved bounded saved-path-opening performance session (P-246):** "ok continue" authorizes
a baseline on the current P-243–P-245-corrected build, path and coverage from one fully validated
generation-bound result, background loading with cancellation and stale-selection protection,
proof/uncertainty/counting verification, and a before/after comparison using the same workload.
This is the first recommendation only, not batch proof-context optimization or collection indexing.
The retained reduced pilot's 459.105-second validated reopening is neither GUI timing nor measured
attribution to duplicate validation; it must not substitute for the current-build baseline.
Reuse existing measurement tooling and isolated sealed-evidence copies with fresh outputs, identifying
source, executable and evidence/analysis generations for every timing; new measurement-harness code
requires separately approved concrete scope, as does any new loading/cancellation wording or layout.
Preserve full proof replay, evidence validation, independent group-held counts, explicit uncertainty
and generation binding without a global stale-result cache, together with all pre-existing work and
the complete P-243–P-245 handoff, binaries, failures, stronger display assertion and archived snapshot mappings.
Do not restore loose `.cs` files beneath artifacts, restart the full-volume series, investigate the
stopped process, change production budgets, access live AD, recapture, migrate, delete originals,
commit or push; requester policy stays Disabled and the legacy discovery budget stays null.
P-242 steps 1–8 remain complete, step 9 unfinished and step 10 pending; physical-display checks,
P-227, P-240 verification and P-241 remain independently open, with no readiness or activation acceptance.

**The owner subsequently approved the opening-only measurement adapter and proposed loading wording.**
One small, frozen adapter may use isolated copies of retained sealed results, exercise the real saved-section
opening path, and record source/build/generation identity, elapsed time and cancellation response without
regeneration, judging or an old-pilot repeat. Keep the shell's existing test-only access boundary intact.
In the existing Saved result field, use **Loading and validating saved results...** while reading;
both account checks and saved questions then say **Saved results have not been read.** rather than
claiming that nothing was recorded. Navigating away cancels, returning starts a fresh read, and no new
button or layout is approved; this grants no broader measurement or optimization scope.

**The owner approved continuing with a shorter isolated measurement path and verifying opening before timing.**
Use fresh short-path copies and process-start TEMP/TMP isolation, preserve both failed attempts, and require
successful database and current-reader opening before the opening timer starts; do not weaken validation,
rewrite saved generations, or broaden the approved adapter/optimization scope to make the measurement pass.

**The owner approved continuing with the cancellation baseline and the already bounded saved-opening optimization.**
Keep the now-frozen adapter and the two retained opening-baseline executions; cancellation evidence must
distinguish a navigation request queued behind synchronous work from cancellation that actually interrupts
an in-progress read, and any profiler-export failure must remain separate from completed workload results.

**Latest owner requirement — normal readback must not replay expensive analysis (P-248).** Opening an
already judged run or browsing its saved results must not re-execute permission analysis or replay a whole
generation's proofs merely to establish that the results belong to the captured evidence; production-scale
usability is a requirement, not acceptance of a minutes-long readback after a percentage improvement.
The owner clarified that this applies across the completed run: findings are information already decided,
and moving between screens, pages and objects must read saved information rather than repeat judging or
whole-store verification. Fixing only the Saved Tier 0 path section would not satisfy this requirement.
Retain simple, exact evidence/derivation/judgement binding, completion and supported-format checks, explicit
uncertainty and independent holder counts, and refuse unavailable or mismatched results rather than showing safety.
Integrity checking is separate from recomputing conclusions: accepted [0020](decisions/0020-the-seal-detects-corruption-not-tampering.md)
requires corruption verification on opening/export, with the verdict retained only for the protected open-file
lifetime, not repeated per screen or replaced by an on-disk size/timestamp cache; [0030](decisions/0030-the-product-produces-sealed-evidence-never-signed.md)
makes no claim of signed provenance or resistance to deliberate alteration and resealing.
This supersedes the earlier per-opening full-proof-replay requirement for the next readback design, not the
need to establish proof correctly when producing results or to verify that behavior offline; the completed
P-246 implementation and all frozen tests, evidence and measurements remain preserved as history.
The concrete reader/publication boundary, integrity lifetime and compatibility/verification scope must be
presented for approval before implementation; this requirement does not authorize simply deleting safety
checks, changing UI presentation, new measurement-harness code, migration, recapture or production activation.
File-fingerprint verification still reads file bytes, so its opening cost must be distinguished from proof
replay and measured rather than described as free or accepted at customer scale without evidence.

**Owner decision, 2026-09-24 — the seal is verified when a bundle is opened, and nowhere else.**
Drawing the Home run list must not hash evidence: it reads state, coverage and completion time directly,
and paying a hash to draw a label made the product unusable once a real bundle was in the library
(measured: 3.7 s per 1.73 GB run, on nine triggers including every navigation to Home, because
`RunStateReader.Observe` and `ScopeOf` each verified the same file). A bundle that has gone bad therefore
reads as finished in the list until it is opened, which is accepted: opening is where the evidence is
about to be believed, so opening is where it is checked. **Export will not verify either.** The owner's
reasoning is decisive and closes the question rather than deferring it: an export is CSV, and a hash of
the source database says nothing about a text file that anyone can edit afterwards — so verifying on
export would cost real time and protect nothing. This is not a weakening of [0020](decisions/0020-the-seal-detects-corruption-not-tampering.md);
that decision already requires the verdict to be held for the open-file lifetime and **not repeated per
screen**, and already refuses a size/timestamp cache as a substitute. Per-navigation hashing was a defect
against it, not a trade-off within it. The product defends against corruption — a truncated file, a bad
sector, a half-finished copy — and makes no claim against deliberate alteration, per
[0030](decisions/0030-the-product-produces-sealed-evidence-never-signed.md). It is offered free to
administrators who want to understand their own risk; misuse by the person running it is not a threat
it is built to answer.

**Owner-approved P-248 checkpoint 1:** “begin” authorizes the local implementation branch, explicit
analysis-attempt publication state, a protected selected-run reading lifetime, and findings/filter/rule
execution reads through that boundary, with isolated regression and rebuilt deliberate-defect verification.
Stop at that checkpoint; it does not authorize the later control/path/LAPS/classification conversion,
database-schema or UI changes, new measurement tooling, migration, recapture, activation, commit or push.
The owner requires a clean replacement of the flawed design, not parallel production implementations,
dead code or permanent transition scaffolding; preserved historical evidence is not a reason to retain
obsolete production code. Preserve the existing instruction-file edit and all retained P-243–P-246 work.

**Owner-approved P-248 checkpoint 2:** continue on `p248-stored-readback` with saved control-edge
and permission evidence, the existing Full Control/ownership conclusions used by those lists,
saved Self-Membership answers, and forward/reverse membership attribution. Replace browsing-time
analysis with saved-result reads through checkpoint 1's protected selected-run lifetime, preserving
exact evidence/derivation/judgement binding, supporting evidence, independent holder/member/route
counts, resource scope and explicit incomplete results. Preserve pre-existing edits, including the
work queue, and all historical artifacts; isolate TEMP/TMP before loading tests and explicitly rebuild
both deliberate defects and restored code. This approval does not reopen checkpoint 1's completed
mutation work or authorize UI/schema changes, later checkpoints, live AD, activation, new measurement
tooling, commit or push; P-241 and unperformed physical-display checks remain open.

**Owner-approved P-248 checkpoint 3:** “approve begin implementation” authorizes the proposed saved
Tier 0 path, path-input and requester-coverage readback replacement through the protected selected-run
lifetime, preserving result-production checks, exact generations, supporting evidence, uncertainty,
independent counts and existing presentation. Verification is synthetic/offline with rebuilt deliberate
defects; checkpoint 1 and 2 verification campaigns are not restarted, and P-241 remains open.
UI/schema changes, live AD, activation, new measurement tooling, commit and push remain unauthorized.

**Owner-approved checkpoint 3 storage correction — zero backward compatibility.**
Before this correction, `ownership_seed` stored routes and a classification fingerprint, not the full
`Tier0Classification`; `PathInputs.Classifications` had to be reconstructed by the classifier.
The owner approved storing the complete classifications and advancing the judgement format, explicitly
requiring **zero backward compatibility because this product has never shipped**. This supersedes
checkpoint 3's no-schema-change and existing-format compatibility limits only: refuse older formats,
with no migration, legacy reader, empty-evidence substitute or hidden replay fallback. Preserve original
evidence/results and historical verification separately; regenerating old results remains outside this
approval, as do UI changes, live AD, activation, new measurement tooling, commit and push.

**Checkpoint 3 is implemented and offline verified in judgement format 39.** All 5,665 offline tests
and all 21 new focused coverage cases pass; every new case detected a relevant defect across four
explicitly rebuilt variants, with successful restoration builds and unchanged original artifact metadata.
The retained verification handoff is
`next/artifacts/p248-c3-6cec41d134044638b2d3d70df7528756/handoff.json`.
Later P-248 checkpoints, P-241, physical-display checks and customer-scale opening-cost acceptance
remain open; this is neither complete P-248 nor complete Stage 7, and requester activation is unchanged.

**Owner-approved P-248 checkpoint 4:** “approved and begin implementation” authorizes judgement
format 40 with a complete all-computer LAPS inventory produced during judging, saved-result reads
through the protected selected-run lifetime, and requested-finding-only SEC-090/093 route reads
with recorded support lengths. Inventory includes healthy, disabled and domain-controller computers
independently of findings; captured support, scoped capture shortfalls and incomplete results survive.
Inventory now requires a completed saved product rather than calculation before judging: the existing
refusal panel says **This run has no saved LAPS inventory.** Raw object attributes remain readable.
Missing or unreadable account flags must remain Unknown rather than Disabled; the existing skip-reason
column says **Account state unknown** or **Domain controller; account state unknown** as applicable.
No layout or finding-text changes are authorized. Replace the old analytical inventory reader rather
than retain a fallback, refuse older formats with zero backward compatibility, and do not regenerate
original results. Verification is synthetic/offline with TEMP/TMP isolated before test-assembly loading
and every new behavior check witnessed by rebuilt deliberate defects and restoration builds; do not
restart checkpoint 1–3 verification campaigns. Preserve intervening work and all historical artifacts,
including failures; P-157, P-174, P-241, later permission/navigation checkpoints, physical-display checks
and customer-scale opening-cost acceptance remain open. No live AD, activation, production-budget
changes, new measurement tooling, commit or push is authorized.

**Checkpoint 4 is implemented and offline verified in judgement format 40.** All 5,705 offline tests
pass, including all 5,665 historical cases and 40 new cases passing under coverage; every new case
detected a relevant defect across seven explicitly rebuilt variants, with successful restoration builds.
The qualified handoff, including retained failed attempts and preservation checks, is
`next/artifacts/p248-c4-6596977645534ef5b49c3893ec5dcd55/handoff.json`.
No original results were regenerated; this completes only the approved LAPS readback checkpoint,
not P-248 or Stage 7, and the independent constraints listed above remain open.

**Owner-approved P-248 checkpoint 5:** “approved and begin implementation” authorizes format 41
saved per-right permission classification, produced during the existing all-object judging stream
and read through the protected selected-run lifetime. Preserve each right's bits, wording, verdict,
reason, original ACE identity/order, inheritance/applicability, captured-schema context and explicit
unclassifiable outcomes; this is not requester authorization, takeover proof or a completed Tier 0 path.
Missing/invalid saved products refuse classification while raw evidence remains readable, with zero
backward compatibility and no migration, regeneration or replay fallback. Keep the grouping, columns,
colors and default-off highlighting, with the approved unavailable/unclassifiable notices, saved-result
counter explanations, per-right reason tooltips and corrected incomplete/order/empty-list statements.
Use isolated offline verification, with TEMP/TMP isolated before test-assembly loading and every new
behavior check witnessed by rebuilt defects and restoration builds; preserve all historical cases,
hashes, artifacts and failures without restarting checkpoint 1–4 campaigns. Hidden navigation, P-157,
P-174, P-241, physical-display checks and customer-scale opening/browsing acceptance remain open;
no live AD, activation, budget changes, new measurement tooling, original-result regeneration,
commit or push is authorized. Approval is not a claim that this checkpoint has been implemented or verified.

**Checkpoint 5 is implemented and offline verified in judgement format 41.** All 5,768 offline
cases pass with no skips, retaining all 5,705 historical cases by test identity; all 63 new cases
pass under coverage and detect relevant defects across ten explicitly rebuilt variants, followed
by exact source restoration and successful restoration builds. The qualified handoff, including
earlier failures, is `next/artifacts/p248-c5-51372c69f37e4fefbaab3133567312c6/handoff.json`.
Saved permission classification retains its evidence and uncertainty without browsing-time risk
replay; unread descriptors are not described as observed noncanonical or incomplete lists.
This completes only checkpoint 5: hidden navigation, P-157, P-174, P-241, physical-display checks
and customer-scale opening/browsing acceptance remain open, with no Stage 7 completion,
activation, original-result regeneration, commit or push.

**Owner-approved P-248 checkpoint 6:** “approved begin implementation” authorizes visible-only
completed-run browsing without changing format 41. Load only the visible listing and selected object
section; resolve the object's captured identity/class before selecting the requested section, without
preparing other sections or their rows. Findings-filter choices load on first Findings display and
belong only to that protected run lifetime. Keep section availability/order, result meanings, columns,
grouping, colors and the existing geometry; replace eager production paths rather than retain a parallel
implementation. An open object belongs to its originating Assets tab: another tab displays its listing
and suspends object reads, while returning reloads the selected section if the run and shared selection
remain valid. Back retains the originating page/position only after checking its protected lifetime,
generation and query; superseding selections cancel reads and reject late success or failure. Tree,
filter and applicable level changes invalidate affected pages but read only the visible destination;
Rules remain whole-run. LAPS starts at its own first page rather than inheriting the Objects page,
without new paging controls or closure of P-174. Leaving Assets cancels work; re-entry retains the
current Objects/root landing behavior. Missing products, changed generations and unpublished attempts
remain explicit refusals, never cached results, empty substitutes or hidden analysis replay.

The approved additional content-area wording is **Loading captured information…**, **Loading saved
results…**, and **This view could not be read.** followed by the underlying reason. Keep the existing
Saved Tier 0 path wording **Loading and validating saved results...**. Loading/refused views do not
present old rows, old finding guidance, zero counts or “nothing found” as current answers; genuine
empty results retain their existing wording. Verification is synthetic/offline with TEMP/TMP isolated
before any test-assembly loading, including discovery; every new behavior check requires a relevant
rebuilt deliberate defect and exact restoration build. Preserve historical cases, frozen values,
measurement tooling, artifacts, failed attempts and intervening work without restarting checkpoint 1–5
campaigns. P-157, P-174, P-241 and independent verification/readiness, physical-display and customer-scale
acceptance remain open; no live AD, activation, budgets, migration, original-result regeneration,
new measurement tooling, commit or push is authorized. Approval is not implementation or verification.

**Checkpoint 6 is implemented and offline verified in judgement format 41:** its corrected protected-read prerequisite passes all 5,784
offline cases, retaining all 5,768 historical cases. All 16 new checks pass under coverage and detect
relevant defects across seven explicitly rebuilt variants with exact restoration; the qualified results
and retained failed attempts are recorded at
`next/artifacts/p248-c6-40e79c89c1e04f049c8ccac4b001e8bc/handoff.json`.
The approved navigation implementation passes all 5,826 offline cases, retaining all 5,784 prior
cases by stable identity; all 42 new cases pass under coverage and detect relevant assertion failures
across five explicitly rebuilt variants, each followed by exact restoration and a passing rebuild.
The qualified navigation handoff and retained failed attempts are
`next/artifacts/p248-c6-navigation-f8a15ebd7cd5463ab874c71f06d2389c/handoff.json`.
This completes checkpoint 6 implementation, not P-248 or Stage 7: P-157/P-174/P-241, independent
verification/readiness, physical-display and customer-scale opening/browsing acceptance remain open.
The owner subsequently authorized committing and publishing this checkpoint; no migration,
regeneration, activation, live access or new measurement tooling was authorized, and completed
prerequisite campaigns were not restarted.

**Owner-approved bounded offline judging diagnosis (P-249):** “Approve bounded offline judging
profiling after identifying the lab build and obtaining an isolated sealed-run copy” authorizes
measurement only after both prerequisites are met. Identify the executable/build for every timing;
the reported previous approximately 40 seconds remains an estimate until comparable baseline
evidence is available, and the current checkout is not proof of the lab executable. Use isolated
sealed-evidence copies offline, with TEMP/TMP isolated before any test-assembly loading or discovery,
and distinguish saved-result production, evidence reads, scope assessment and path preparation.
Preserve original evidence/results, the supplied log, historical measurements, failed attempts and
intervening work; do not restart completed checkpoint or mutation campaigns. This approval does not
authorize optimization, new measurement tooling, live forest access, recapture, original-result
regeneration/deletion, production requester activation/budget changes, UI changes, commits or pushes.
The reported successful lab screen navigation is functional feedback, not physical-display or
customer-scale acceptance.

**P-249 input handoff:** the owner supplied
`C:\Users\jistrand\Downloads\ad.lab-20260919-223420` and confirmed that everything there is a copy,
with the application inside its `secure` folder. Preserve that supplied copy as the intake and use
separate fingerprint-verified working copies for the approved offline investigation. The supplied
application identifies the binaries to investigate; its embedded commit stamp alone does not prove
a clean source revision. This handoff does not authorize new measurement tooling or optimization.

**Owner-approved P-249 profiling driver:** “Approve the dedicated offline profiling driver and bounded
judging profile” now authorizes a separate measurement program for this supplied capture and application
package, superseding the no-new-measurement-tooling boundary only for this driver. Run the normal
17-rule `JudgeAudit` configuration using the fingerprinted supplied libraries, with requester selection
disabled and isolated temporary storage before execution or discovery; do not load the test assembly
or repoint historical benchmarks. Retain provenance, phase timing, result/count checks and all attempts
on fresh working copies without changing production code, security conclusions, budgets or screens.
This approval does not authorize optimization, live access, recapture, original-result changes,
restarting completed verification campaigns, commits or pushes.

**P-249 follow-up scope after the two unsuccessful profiler attempts:** the owner requested
inspection of the second failure and preservation verification **without rerunning judging**, then
authorized retrying the canceled inspection. This follow-up is inspection only, not a further
profiling attempt, driver repair, build, test run or optimization; retain both failed attempts and
any unsuccessful verification records alongside the corrected verification result.

**Owner-approved P-249 build-only repair:** “Fix the profiling driver and validate its build without
rerunning judging” authorizes correcting only the dedicated driver's build/reference wiring and
compiling a separate copy of the failed generated runner. Preserve the supplied binaries, original
generated files, failed attempts and previous verification records; do not invoke benchmark setup,
judging, readback, test discovery or profiling during this repair. A passing build is not a timing
measurement, execution validation or approval of any optimization.

**Owner clarification for P-249:** the supplied run is already a copy; stop creating additional
evidence snapshots and repeating broad preservation reports during driver repair. Keep only the
input/build identification needed for valid measurements, leave existing historical artifacts alone,
and focus on the fix with brief updates. This does not request deletion or a further judging run.

**Owner resumed P-249 profiling after the build repair:** “ok do the profiling” authorizes the
bounded offline profile with the repaired driver and supplied libraries. This supersedes the
build-only pause, not the restrictions on production changes, optimization, live access or budgets.

**Owner-approved bounded P-249 optimization:** implement command/parameter reuse and transaction-local
deduplication of identical schema support in `PermissionClassificationStorage.Write`, keeping one
transaction per object, exact conflict checks, cancellation/rollback, all permission rows and proof
binding unchanged. Approval includes a separate matched before/after configuration against newly built
libraries, focused regression checks with rebuilt deliberate defects, and offline remeasurement; the
supplied-binary benchmark remains frozen. No shared-proof redesign, cross-object batching, format/UI
change, live access, activation, new production budgets, commit or push is authorized.

**Owner-selected order for the P-248 review follow-up:** address P-250 (evidence-reader lease
disposal), then P-251 (exact saved-interpretation sharing), then P-252 (subject-specific path reads).
Use separate bounded sessions; the order does not authorize later format/UI changes, optimization
or new measurements in the lease-repair session. Keep updates brief and do not restart broad
preservation inventories for the supplied copied run.

**Owner-approved bounded P-251 implementation and offline verification:** “Approve the bounded P-251
storage change, separate comparison adapter and offline verification” authorizes generation-local
sharing of exact saved permission interpretations, judgement format 42 and its selected-object reader,
without changing interpretation calculations, individual permission identities/order/duplicates/counts,
schema support, uncertainty or security conclusions. Retain exact-content checks after indexed lookup,
entry/generation binding, one transaction per object, cancellation/rollback and explicit refusals;
replace the old repeated representation with no compatibility reader, migration, analysis replay,
forest-wide memory cache or UI change. The separate P-251 comparison adapter must preserve the frozen
P-249 tooling, establish an identified original-writer baseline before production edits, then use the
same sealed input and procedure for three matched pairs with alternating run order and fresh processes;
retain every timing, build/input identity and failure. Approval includes focused offline correctness
checks with rebuilt deliberate defects and restoration builds, with TEMP/TMP isolated before test
assembly loading or discovery; a smaller store alone is not an accepted judging-speed fix. Preserve
historical evidence, hashes, verification artifacts and pre-existing work; no live access, recapture,
requester activation, production budgets, computation sharing, commits or pushes are authorized.

**Owner-approved bounded permission-entry command reuse:** “Approve the bounded permission-entry
command-reuse change and offline verification” authorizes a lazily prepared insert/read-ID command
and 21 reusable parameters in `SharedPermissionStorage`, with disposal at the four transaction-owning
sites in `ControlEdgeStorage` and `PermissionClassificationStorage`. Keep judgement format 41, the
SQL and stored values, exact keys, fingerprints, entry identities/order/duplicates/counts, shared-proof
behavior and security conclusions unchanged; no interpretation/computation sharing, reader/UI change,
cross-object batching, run-wide cache, discovery or budget change is included. Use the frozen P-251
comparison adapter unchanged, an original control before production edits and three matched pairs
with alternating order and identified fresh-process builds; retain supplementary invocations and
failed attempts separately, and verify the other affected writer paths with focused offline scenarios.
Approval includes new reuse/lifetime/value/rollback checks and relevant existing storage checks, with
TEMP/TMP isolated before test loading/discovery and rebuilt deliberate defects/restoration for every
new behavior check. Accept only repeatable whole-judging improvement with identical security outputs
and no material allocation, memory or readback regression; otherwise restore the original and retain
the trial without broadening it. Preserve pre-existing work and historical evidence/artifacts; no new
measurement program, live access, recapture, commits or pushes are authorized.

**Owner-approved current-object permission-reuse trial:** “OK TEST IT” authorizes testing the
reviewed first scope: reuse the current object's already-read captured permissions when offering that
object to rules, including repeated ownership lookups, while preserving independent mutable inputs
for each lookup and expiring reuse at the end of that object's processing. Preserve exact-name and
ambiguous-name behavior, other-target lookups, missing/unreadable/empty distinctions, resource scope,
reader lifetime and evidence/generation binding; a missing permission provider stays missing. Keep
format 41, all security decisions, path-validation reads, discovery, budgets and UI unchanged. Use the
frozen offline comparison and focused regression checks with rebuilt deliberate defects/restoration,
isolating TEMP/TMP before test loading/discovery and retaining pre-existing work, original evidence,
all measurements and failed attempts; no new measurement program, live access, recapture, commit or
push is authorized. This is permission-reading reuse, not interpretation sharing or removal of checks.

**Owner-approved bounded diagnostic-only timing and verification:** “Approve the bounded
diagnostic-only timing and verification scope” authorizes an unchanged offline reproduction check
using the supplied build/evidence, then a separate source-matched diagnostic build and diagnostic
copy of the existing runner to account for elapsed judging time, not another optimization. Identify
actual binaries, source relationship, runtime, machine and host context; a fast developer-machine
run must not be presented as an explanation of the lab's 108 seconds, and a lab execution, if needed,
must be an explicit offline command/package using copied evidence rather than another capture.
Keep frozen benchmarks and normal production untouched; aggregate exclusive phase timings and work
counts, label nested detail and the unattributed remainder, include enumeration advancement, and
separate permission reading/interpretation/storage, other writes/rules, scope/ownership, path-source
validation/calculation and publication from completion-screen loading. Verify result equivalence,
timing attribution and instrumentation overhead with an uninstrumented/diagnostic/uninstrumented
comparison and rebuilt deliberate defects/restoration; stop and state the limitation if source
equivalence, reproduction or overhead cannot be established. Isolate TEMP/TMP before test loading
or discovery and preserve all prior work, original evidence, measurements and failed attempts; no
rule/result/format/UI change, discovery/budget change, live access, recapture, deletion of originals,
commit or push is authorized.

**Owner-approved pre-P-248/current offline judging comparison:** “lets do it” authorizes isolated
rebuilds of pre-P-248 `efb6fb076ee586cb6fe5dfee8ade8457a630a82e` and current
`2c2b3e3b305347c1cc85ce6beb84d3a3470ead27`, plus a separate small comparison runner that handles
their different saved-judgement formats without changing the frozen runners. Use the same existing
copied evidence and derivation, evaluation date, rules, runtime and disabled requester policy; run
old/current then current/old in four fresh processes without added diagnostic instrumentation, compare
common results, and report P-248's additional saved products separately. This is a contemporary
source-rebuild comparison, not reconstruction of an old lab executable or timing; preserve current
uncommitted work and all original evidence, measurements and failures, isolate TEMP/TMP before loading
any test assembly, and do not recapture, access live AD, optimize, change production behavior, commit
or push. No older audit or application needs to be supplied by the owner for this comparison.

**Owner-approved P-249 per-object permission storage correction:** “Create the branch and implement
the bounded per-object permission storage correction” authorizes work on
`p249-object-permission-storage`, created from `p248-stored-readback` at `2c2b3e3`, with existing
uncommitted work preserved. Replace the per-entry classification persistence with one complete,
ordered saved permission-result payload per object and separately shared schema support; classification
alone must no longer populate the shared control-proof permission tables, while their actual control
proof uses remain intact. Keep permission calculations and public results unchanged, including every
entry, original ordinal, duplicate, raw value, per-right verdict/reason, applicability, inheritance,
captured-schema support, resource scope and missing/empty/unreadable/incomplete distinctions. Preserve
exact evidence/derivation/judgement/object binding, independent counts, publication checks, one
transaction per object and cancellation/rollback; the matching selected-object reader reads saved
answers without analytical replay. This authorizes a distinct new judgement storage format and its
reader, not reuse of the rejected format-42 interpretation-sharing trial, compatibility readers,
migration, UI changes, cross-object batching or a forest-wide cache. Remove superseded production
write/read paths and unused helpers as part of the same correction, not as later cleanup; retain
historical source/tests/fixtures, frozen benchmarks, measurements and failed attempts separately.

Use the retained offline comparison procedure with a separate adapter copy extended to verify every
saved permission interpretation as well as the common results; do not modify frozen runners or
restart completed profiling/mutation campaigns. Run a current control before editing production,
then candidate/candidate/current to complete four fresh-process runs on identical copied inputs,
evaluation date, rules, runtime and disabled requester policy, without added diagnostic timers.
Approval includes focused correctness and damaged-data/binding/order/schema-conflict/cancellation
checks with rebuilt deliberate defects and restored builds, and measurement of judging, output size,
allocations, memory and selected-object reading; isolate TEMP/TMP before any test loading/discovery.
Adoption requires a repeatable whole-judging benefit with identical answers and no material readback,
memory or cancellation regression, not merely fewer writes; otherwise stop and retain the trial
without leaving parallel production implementations. The earlier pre-P-248 comparison is complete
and must not be repeated; laboratory results do not establish nine-domain production performance.
No live AD, recapture, original-result deletion/regeneration, discovery activation, production budgets,
rule/security-result changes, commit or push is authorized, and implementation needs no further
approval within these boundaries.

**P-249 trial disposition, 2026-09-21:** the approved four-run comparison is complete, with every
saved permission answer and all common results matching, but the format-43 candidate is **not adopted**:
repeatable faster judging did not satisfy the no-material-regression gate because peak memory,
full-heap collection frequency and maximum selected-object read latency increased. Original format-41
production and matching tests are restored; the candidate and its verification remain separately at
`next/artifacts/p249-object-storage/comparison-result.json`. P-254/P-255 keep the full-suite failures
explicit, and neither this trial nor its lab speed gain establishes nine-domain production acceptance.

**Owner-approved P-200 SQLite-cache comparison:** following preparation, “Run the bounded 64 MiB
writer-cache comparison” authorizes the four-run comparison, its separate adapter changes and
isolated candidate build described below, but not adoption or a production default change.
The earlier P-200 reader-cache experiments remain recorded as historical results for their builds,
inputs and combined settings, not evidence that reader-cache tuning cannot benefit today's code.
Do not rerun those historical builds as this comparison's baseline: use fresh current-build controls.
A separately bounded current-build reader-cache experiment would be new evidence, not an unnecessary
repeat; the proposed writer-only first contrast does not rule it out or authorize it automatically.
The proposed first contrast keeps the restored format-41 implementation and changes only the single
judgement writer connection's `main.cache_size`: its observed default versus `-65536` (64 MiB).
That is an experimental allowance, not a hard process-memory cap, a proposed production default or
a budget for the nine-domain forest; evidence/derivation/selected-object readers, memory mapping,
temporary storage, page size, journaling, durability and transaction boundaries remain unchanged.

Use a separate copy of the retained full-answer comparison adapter and isolated builds,
leaving active production and frozen runners untouched; reuse the existing sealed 2026-09-19 copied
input, derivation, evaluation date, 17 rules, runtime and disabled requester policy without new captures
or extra preservation snapshots. First verify the current default through its real writer in a
separate untimed preflight process; stop if it is already at least 64 MiB rather than claiming an
increased-cache comparison that changed nothing. Run a fresh current control before introducing
the isolated candidate change, then verify the candidate's effective setting in an untimed preflight,
with a rebuilt negative control that omits the change and an explicitly rebuilt restoration.
Only then run candidate/candidate/current, completing four fresh uninstrumented judging processes;
keep settings checks, semantic comparisons and tests outside the measured interval.

Compare every saved permission answer and the existing common results with exact input/generation
binding, plus whole judging, CPU time, result size, allocations, memory, GC and selected-object reads;
retain forced cancellation/rollback checks instead of relying on a timer that fires after a read ends.
Use short isolated TEMP/TMP before any test loading or discovery, rebuild new deliberate defects and
restorations, and preserve failed attempts and the unresolved P-254/P-255 qualifications.
More cache memory is an intended trade-off, not an automatic failure: report its absolute cost,
observed growth and read/cancellation effects alongside both timing pairs without inventing an
acceptance threshold from the lab. This comparison alone authorizes no adoption, additional cache
sizes, tuning of other connections, UI changes, live access, recapture, discovery activation,
production-budget changes, commits or pushes; execution within this bounded scope is approved.

**P-200 writer-cache comparison completed, 2026-09-21:** effective writer settings were verified at
2,000 KiB for the current build and 65,536 KiB for the isolated candidate; the only candidate source
change was the cache pragma, with SQLite's derived spill threshold following that allowance.
The four current/candidate/candidate/current runs took 51.675/46.675/229.851/48.325 s and every saved
permission answer and all 28 comparison categories matched, but the long second candidate means
no repeatable speed benefit is established; it is retained rather than discarded or rerun.
Its existing object-processing interval grew from 37.786 to 214.474 s between candidate runs,
without establishing why; mean peak process memory rose from 289.153 to 367.147 MB and result size
was unchanged. Forced cancellation/rollback/retry checks passed on both builds after rebuilt negative
controls and restoration; active production, tests and frozen historical runners were never changed,
and no setting is adopted. `next/artifacts/p200-writer-cache/comparison-result.json` retains build
identities, settings, complete results and limitations; P-254/P-255 remain unresolved, and neither
current reader-cache tuning nor nine-domain production performance is settled by this writer-only trial.

**Bounded saved-permission blocks — design-only handoff:** following the external review and its
corrections, the next deliverable is a concrete storage-and-read contract and bounded comparison plan
for owner review, not implementation, new measurement code or execution approval. Keep evidence →
derivation → judgement and completed-run saved answers; the candidate under discussion changes only
permission-classification persistence and retrieval inside SQLite. Preserve the analysis stages,
genuine control-proof products, one transaction per object, cancellation/rollback and generation
publication; exclude cross-object batching, parallel workers, cross-generation reuse, incremental
findings and external payload files from this first candidate. Reviewer recommendations are proposals,
not newly accepted product decisions, and any visible browsing behavior or wording needs approval.

The predecessor was subsequently inspected at
`C:\Users\jistrand\source\repos\razamus\SecureAD\src` (the alternative lab profile is
`C:\Users\ba.admin\source\repos\razamus\SecureAD\src`). Its
`SecureAD.Infrastructure/Storage/MaterializedAclPayload.cs` demonstrates binary records with a local
string dictionary, but `DirectAceWriter.cs` feeds it normalized entries from
`SecureAD.Core/Security/AceNormalizer.cs`: generic rights are expanded, entries sorted and duplicates
removed. That payload lacks Next's original ordinals, callback application data and richer saved
answers; its nullable-string encoding merges null and empty and its reader materializes the whole
object. The predecessor also retains per-entry rows and computes permission aggregation during
object-detail loading in `SecureAD.UI/ViewModels/ObjectDetailPanelViewModel.cs`; inherit the technique,
not its evidence semantics, workload or timing baseline. Its `SecureAD.Infrastructure/Findings/FindingsService.cs`
uses separate readers for parallel evaluators, not a shared connection that would justify parallelizing
Next's existing loop.

The draft contract must make the following concrete before any implementation:
- Ordered SQLite payload blocks and their searchable object/page metadata, bounded encoding and
  decoding buffers, dictionary scope/lifetime and explicit overflow/continuation for an oversized
  entry, string, schema-support record or application-data value; no truncation or arbitrary security
  processing limit disguised as a storage bound.
- Lossless original order, ordinal, occurrence position, duplicates, raw masks/types/flags, GUID
  presence flags, application data, owner/descriptor states, errors, per-right verdicts/reasons,
  applicability/inheritance, schema support, resource scope and missing/empty/unreadable/incomplete
  distinctions; saved interpretations remain distinct from authorization, takeover and Tier-0 paths.
- Exact evidence/derivation/judgement/object binding and reference integrity, independently reconciled
  object/entry/right counts, ordered manifests, block sequence/length/offset/integrity checks,
  complete-object publication and explicit refusals for missing, duplicated, damaged or unsupported
  data; a truncated payload and a correspondingly truncated manifest must not validate each other.
- A genuinely bounded read contract and identified consumers: first page, continuation, total counts,
  ordering/grouping/filtering and cancellation; never silently return a partial object from a
  whole-object API or infer totals/risk from loaded rows. Partial loading is not incomplete captured
  evidence, and a complete-object result must not be rebuilt eagerly behind the paging API.
- Stage-aware interactions: in the scoped flow the first pass records descriptor coverage and
  candidates; detailed control assessment arrives after admission. Coordinate within producing stages,
  not by retaining every object until all later products exist. Schema interpretation is already
  memoized by `PermissionClassificationProducer`; writer-side reuse must still detect conflicting
  values for the same identifier and cannot cache rolled-back database identities as committed.

Keep the two experimental questions separate: first bounded chunking/readback using the same encoding
as the retained format-43 design where practical, then compact binary encoding of that bounded
representation. Format 41 remains the production reference; format 43 changed several mechanisms and
its historical timings are not a fresh control. Define first-use/first-page, subsequent-page and full
object measurements separately, compare every answer across all blocks, and include whole judging,
CPU, output size, allocations, peak memory, actual GC pause time and cancellation. Do not call reading
one page a whole-object speedup, or choose production limits from the small lab; extra 35 MB or a
46 ms read is not by itself proof of an unacceptable trade-off. Any later experiment needs its own
approved bounds, current measured control before optimization, unchanged-input/build/runtime provenance,
and retained outliers; do not silently restart completed campaigns or modify frozen runners.

**Remaining diagnostic questions and evidence anchors for this review:** the returned BAWK1 offline
reproduction took 133.74 s, including 115.12 s of object processing and about 7.03 s of nested rule
clocks, leaving about 108.09 s outside those clocks in that interval; this is not the original reported
108-second audit reconstructed. The supplied libraries and input also ran in about 26.86 s on
S2DMEASOFT; BAWK1 used .NET 10.0.10/eight logical processors and S2DMEASOFT .NET 10.0.12/twenty,
without proving which host/runtime/work effects explain the gap. Returned lab records remain under
`C:\Users\jistrand\Downloads\judging-reproduction-results-20260921-010007-4ef019f0d6d24b3d88e0ee5a750dba7c`.
The latest local diagnostic ledger attributed about 16.26 s of a 27.69 s run to permission storage
including nested work, but controls of 34.18/31.11 s did not establish its timing overhead; do not
double-count children or claim that ledger explains the slow lab or 229.85 s cache-trial execution.
Use `next/artifacts/judging-walltime-diagnostic/timing-continuation/completed-comparison.json`, not
the earlier paused handoff, for that qualification. Pre-P-248/current rebuilt Next comparisons show
9.677→26.956 s mean judging, 23.245→352.264 MB output and 98.6% of the added elapsed cost in the object
interval, but the current build additionally produces required saved products: this is not identical
workload or a comparison against the predecessor application.

All trial outcomes, identities and failures remain in `next/artifacts/`:
`p249-pre248-comparison/comparison-result.json`, `p249-storage-comparison/result.json`,
`permission-entry-command-reuse/comparison-result.json`, `current-object-permission-reuse/comparison-result.json`,
`p251-storage-comparison/comparison-result.json`, `p249-object-storage/comparison-result.json` and
`p200-writer-cache/comparison-result.json`. Active production is restored format 41, with no trial
optimization adopted; P-254/P-255 remain open. The design session should extend an appropriate
specification under `docs/specs/` (or create a clearly marked draft specification if none fits), not
a new session-history document or tests comparing prose to code. Read the existing judgement specs
first, preserve uncommitted work and all original/frozen artifacts, and stop at a concrete proposal
for owner approval; no new builds/tests/profiling are required to draft it, and no live access,
recapture, discovery activation, production-budget change, UI change, commit or push is authorized.

The concrete proposal is now [P-249: bounded saved-permission blocks — draft](specs/P249-SAVED-PERMISSION-BLOCKS-DRAFT.md).
It specifies the lossless storage/read contract, actual caller changes and separately bounded chunking
and encoding comparisons; the subsequent bounded trial approval below supersedes its original design-only
restriction for candidate B only, while format 41 stays active. The historical outcomes and unresolved
qualifications above are unchanged; candidate C and production adoption remain unapproved.

**Owner-approved final bounded P-249 trial:** after clarifying that paging already exists for object
listings and control/membership results, but not for the complete permission list inside one object's
Permissions section, the owner selected **“Approve the complete final trial”** in response to the
explicit scope question covering implementation, offline verification, the Permissions-screen change
and four comparison runs. Implement the draft's **B / chunked JSON** storage and genuinely bounded
readback in an isolated candidate, including its proposed principal/entry paging and explicit large-value
continuation presentation using the existing app pattern; do not change existing object-list or
control/membership pagers. This includes the separate comparison-adapter work and contrast I:
four fresh format-41/candidate/candidate/format-41 judging processes, with the first current control
before candidate optimization, the draft's bounded reader workloads and complete saved-answer comparison.
Preserve the input/build/runtime identities, every original occurrence and interpretation, genuine proof
products, one transaction per object, rollback and generation publication; isolate TEMP/TMP before test
loading/discovery and rebuild new deliberate defects and restorations. Active production remains format
41; trial UI changes belong to the isolated candidate, and adoption requires a subsequent owner decision.

The owner is being asked by a customer to provide a usable product: **this is one final bounded attempt,
not an open-ended storage optimization campaign**. If it does not demonstrate a worthwhile benefit,
retain its results and return to **finishing Stage 7, then the remaining rule coverage**, rather than
starting another storage experiment; report practical speed/read/memory/cancellation trade-offs without
inventing a lab-derived acceptance threshold. No binary-encoding candidate C, cache tuning, fifth judging
run or extra run to chase a better timing is authorized. Preserve all pre-existing work, historical
campaigns/outliers and the unresolved P-254/P-255 qualifications; the 133.74-second and 229.85-second runs
remain unexplained. No live AD, recapture, original-result regeneration/deletion, discovery activation,
production-budget/security-rule changes, migration/legacy readers, commit or push is authorized.

**Final-trial execution checkpoint — unfinished, not a candidate verdict:** the first fresh format-41
control and its bounded selected-object whole-reading workload are retained under
`next/artifacts/p249-final-b/`, with the execution plan, exact source/build/input identities and all failed
attempts. The owner explicitly resumed from that checkpoint without repeating run 1. The preservation
check had found a changed timestamp on the retained original judgement's
SQLite shared-memory companion file during selection preparation; the sealed database hashes still match,
but the prior companion-file bytes were not hashed, so full artifact preservation cannot be claimed
(`P-256`). Protected immutable access and write-denying input protection are now verified with a rebuilt
deliberate defect and restoration; the historical uncertainty remains. B's isolated storage now holds block
framing, exact value fragments, independent producer/source expectations, the publication ledger, exact
large-value continuation, schema reuse with conflict refusal, and the whole per-object answer: descriptor,
trustee, entry and right records, the `pc_group` and `pc_occurrence` directories a principal selection needs,
the object and group projections computed with the screen's existing risk, denial and rights-summary rules,
an independent stored readback that decodes every record again and compares typed values rather than only
digests, and one transaction per object wired through the ledger with rollback and cancellation. Entry
application data required exact byte values, so the value stream was extended to carry bytes as well as
UTF-16 through the fragment layer's existing byte path. 154 focused offline checks pass, with ten rebuilt
deliberate defects this session; one of them found a real fault in the new code, where two places decided
one question about whether a value is stored by reference, and one check was split because it carried two
independent claims. **The candidate still writes format 41 and is not qualified**: generation publication in
the candidate writer, bounded readback, the Permissions screen and the remaining B/B/A runs are all still
owed. Those must land as **one change**, because a candidate that writes blocks before its reader exists
would produce a judgement it cannot itself open, and format 44 is selected only when that switchover is
complete; the binding adapter carrying captured object, coverage and descriptor identities also needs a new
public read path in `SecureAD.Evidence`. `next/artifacts/p249-final-b/continuation-04/result.json` records
the bounded checkpoint and verification limits. Format 41 remains active, slot 1 is consumed and must not be
silently repeated, and neither a completed comparison nor a benefit/failure of B has been established.

**Owner priority reaffirmed:** continue the approved storage trial now, before finishing Stage 7 and
the remaining rules, so a worthwhile storage improvement can be in place for later rule work. This
continues the existing B-only implementation and remaining B/B/A comparison, not a new experiment,
permission to repeat run 1 or approval to adopt an unverified candidate; improvements to saved-permission
storage do not promise that every future rule's own calculation will become faster.

**Owner decision, 2026-09-22: small fixed memory differences are not an acceptance criterion.**
His words: *"memory is less of a concern to me. most modern systems have 16 GB of memory, if I run this
on a server it would have a lot more than that, I don't want to quibble over 40 MB of memory."*
A peak working set measured in tens or low hundreds of megabytes is therefore **not** a reason to
reject a candidate or to complicate a design, and no session should trade clarity, fidelity or speed
for a saving of that size. This supersedes the memory half of the P-249 adoption gate recorded above:
judging speed, answer equality, browsing responsiveness and cancellation still decide adoption, and a
memory figure is reported as information rather than weighed against them. It does **not** retire the
*other* two regressions that stopped format 43 — maximum selected-object read latency and full-heap
collection frequency — because those are felt as a screen that stalls, which is a responsiveness
question and not a memory one.

**What this decision does not yet settle:** whether memory that grows with the size of the forest is
equally unimportant. Tens of megabytes on a laboratory of 8,383 objects is a different thing from a
design that holds whole objects, whole principal lists or whole result sets at 347,000 objects and
5.9 million access control entries, where the same shape reaches many gigabytes. Bounded reading is
still required for **time to first screen** and for cancellation, not only for memory. Do not read this
decision as permission for unbounded growth, and do not read it as a prohibition either; ask the owner
when a specific design actually raises it.

**Owner-approved next implementation session: one object's saved path evidence.** After reconciliation
against the existing specifications, the owner selected "Approve for next implementation session" for
the following bounded display scope and wording; this preparation session does not authorize code changes.
The subsequent "begin implementation" request authorizes this bounded implementation with the same
wording, proof and preservation boundaries; measurements remain paused and requester activation disabled.

- Add **Saved Tier 0 path** immediately after **Control edges** in the object view, with three groups:
  **Saved result**, **Recorded route**, and **Coverage and limitations**.
- Word the saved result **Supported route recorded**, **This object is a Tier 0 target**,
  **Not determined**, or **No saved path result**, as applicable; failed validation instead says
  **Saved result unavailable** with its reason, never an empty or negative security answer.
- Show the saved ordered route steps, destination, supporting evidence and assumptions. Label length
  **Shortest proven route**, stating that unsupported alternatives might be shorter; a fixed target's
  zero distance is not an extra hop. Permission to change permissions is not account takeover, obtained
  membership is not an observed successful Add, and a supported route is not proof of live-operation success.
- Keep missing captured evidence, unsupported analysis and unresolved identities distinct. Under
  **Automatic account checks**, show **Not requested**, **Required inputs unavailable**, or
  **Supported questions evaluated** from the typed saved execution-coverage verdict, never from counts;
  a completed supported scan does not establish forest-wide coverage or safety.
- Read and validate saved results from the same exact generation only when the section is opened;
  do not discover accounts, calculate new paths, write results, contact AD or present an older result
  as a failed/unfinished attempt's current result. Preserve original permission supports, independent
  group-held counts and passive readback, including validation of recorded proof questions.
- Verification is synthetic/offline, with rebuilt deliberate-defect checks and normal laptop/external-
  monitor display checks; unperformed checks remain outstanding. No measurement, optimization,
  requester activation, new budget, recapture, original-artifact deletion, commit or push is included.

This makes already-saved analysis inspectable, not broader detection coverage or Stage 7 completion.
SEC-071 finding production, P-143 declarations, wider compositions, summary counts and remediation remain
separate work; P-242's unfinished measurement/acceptance steps and the independent verification issues
remain open. No separate graph screen or changes to existing ownership/permission findings are included.

**Saved-path presentation is implemented and offline verified; physical-display checks remain outstanding.** The retained verification
at `next/artifacts/stage7-saved-path-presentation-validation/24b9a2507ad64923b6943b1c957083c9/verification-df1a23bdf1f04c359a0e97f2bd4a24e3/`
records all 65 new checks passing under coverage collection and all 65 detecting deliberate defects
across ten explicitly rebuilt variants, with successful restoration rebuilds and all six mutation-target
source hashes checked against the restored baseline. The successor verification at
`next/artifacts/stage7-saved-path-presentation-validation/24b9a2507ad64923b6943b1c957083c9/verification-full-suite-e6bd37ae0f124ec5934e767971a2c4b5/`
records an explicit Release rebuild and all 5,509 offline tests passing with no skipped cases, matching
test identities and source/executable hashes, and a preservation review finding only the intended
source changes and no existence/length/last-write changes across the 15,215 original artifact records;
the earlier run without a final result and the subsequent 5,507/5,509 failure remain retained, physical
laptop/external-monitor checks remain unperformed, and this does not accept P-242 measurements,
complete Stage 7 or close P-227, P-240 verification or P-241.

## Stage 7 first checkpoint: saved path inputs

**Owner-approved implementation scope:** save source-bound path inputs in new Judgement generations,
with passive validation/readback and no reachability verdicts, distances, tier counts or screen changes.
Reuse the authoritative Tier-0 classifier; fixed anchor targets are distinct from effective membership
and assessment-admission relationships. Preserve individual uncertainty scopes, resource context,
permission proof and generation binding without treating a permission or admission as a completed path.
Verification is synthetic/offline, with mutation checks and explicit rebuilds; requester discovery,
live access, optimization, commit and push are not authorized. P-142 enterprise CA classification,
P-143 declared assets and Self-Membership requester discovery remain later Stage 7 work; outstanding
Stage 6 acceptance is not a blanket prerequisite.

**No backward compatibility is required.** The owner explicitly clarified this when approving the
checkpoint: new formats need neither migration nor legacy-reading support. Existing evidence,
historical tests, failed validation artifacts and pre-existing uncommitted work must still be preserved.

## Stage 7 second checkpoint: first bounded path calculation

**Owner-approved scope; implemented and offline verified as P-229.** Calculate and save qualified existing membership routes
and terminal DACL-control routes to the shared classifier's fixed Tier-0 targets, without screen changes.
This is not yet an engine for arbitrary chains through account takeovers.

- Fixed targets have distance zero; effective members and assessment candidates are not extra destinations.
- Follow qualified captured security-group membership links, including nested and primary-group links
  where their evidence supports them; retain and count the actual links rather than collapsing a chain.
- An established `WRITE_DAC` or fully established current-owner DACL-rewrite proof may terminate at a
  fixed target only for its supported operation and resource. It does not establish the ability to act
  as the target account. Group membership alone does not establish a member's authority to exercise
  a group-held permission; without the required requester/resource proof, that join remains Unknown.
- General membership-write permission, password reset, key-credential writes, replication rights,
  `WRITE_OWNER`, unresolved owner transitions and Self-Membership candidates remain possible or
  unsupported steps, with their evidence and reasons retained rather than promoted to completed paths.
  Admission, expected administration and a Full Control summary are not independent takeover proof.

Reachable requires a fully supported route. Unknown retains relevant missing evidence or unsupported
steps; NotReachable requires excluding relevant possible routes too, never merely finding no definite
route in incomplete inputs. **The current bounded calculation returns Reachable or Unknown; it does
not emit NotReachable while unsupported alternatives remain.** Keep capture gaps, unsupported analysis, unresolved identities and unfinished
processing separate, preserve symbolic uncertainty scopes, and do not invalidate a proven route for an
unrelated gap. Work backward from fixed targets without an arbitrary path-depth cutoff; save one
deterministic shortest proven route, qualifying its length when uncertain alternatives could be shorter.

Bind saved results to the exact Evidence, Derivation and Judgement generations and analysis versions.
Readers remain passive; cancellation or failure must not replace the previous valid result. Preserve
permission supports and group-held counts independently of member and route counts. Verification is
synthetic/offline, with deliberate-defect checks for every new behavior, explicit rebuilds and retained
artifacts; this grants no customer-scale or outstanding Stage 6 acceptance.

P-142, P-143 and Self-Membership requester discovery remain planning work; requester discovery and new
member-expansion activation stay outside this slice. P-227 remains open. No backward compatibility,
tier counts, remediation, screen changes, optimization, live access, commit or push is included.

## Stage 7 third checkpoint: concrete requester DACL permission proof

**Owner-approved scope; implemented and offline verified as P-230.** After preparation against the
saved P-229 baseline, the owner selected “Approve the requester-proof slice”. Establish whether a
particular captured user can exercise an explicit `WRITE_DAC` permission on a fixed Tier-0 target,
rather than transferring a group-held permission to every member without a requester access check.

- Support direct user authorization or one explicit global-security-group membership, evaluating
  all relevant allows and denies in captured order. Requester, granting group and target must be in
  the same domain, and the target must belong to a verified domain naming context. Reuse the existing
  authoritative fixed-target classifier; this narrower new proof does not remove existing routes.
- Retain original permission entries, requester identity, membership support, resource context and
  exact Evidence/Derivation/Judgement generations. Preserve the actual membership and permission
  steps in the saved path explanation; requester proofs do not multiply group-held permission counts.
- This is an offline-verified calculation and passive-readback building block, not production
  requester coverage. Both hosts' scheduling and requester discovery remain unchanged; no manual
  administrator-maintained selection list, screen changes or production processing budget is approved.
- Existing ownership findings and independent owner proofs remain unchanged. No account takeover,
  new ownership-transition inference or hypothetical membership-change step is included.
- Missing evidence, unsupported authorization routes, unresolved identities and work not performed
  remain distinct. Relevant uncertainty must not become a definite route; unrelated gaps must not
  erase one. The bounded calculation continues to emit Reachable or Unknown, not NotReachable.

The examined follow-on route is an own-account addition to a same-domain global security group,
followed only by qualified existing memberships to a fixed Tier-0 target. It remains preparation
work: Self-Membership authorization alone does not establish Add readiness, and an omitted captured
member value does not prove non-membership. A separately justified operation rule is required before
promoting that candidate; this approval does not weaken the existing readiness safeguard or authorize
recapture. Verification of the approved requester slice must cover positive routes, applicable denies,
unsupported contexts, unchanged counts, source mismatches and cancelled publication, with deliberate
defects for every new behavior check and explicit rebuilds. No live access, optimization, commit or
push is authorized.

Judgement format 33 saves these explicit requester answers and their source-bound path steps, with
passive proof validation and unchanged production scheduling. All 5,058 offline tests pass normally,
all 156 focused cases pass under separate coverage, and all 50 new cases detect deliberate defects
with explicit rebuilds and verified restoration. The original evidence, historical validation and
deliberate-defect records are preserved; the final validation summary is
`next/artifacts/stage7-requester-dacl-validation/0bf5064e17794e3fa8a34630dd2cb31a/final-summary.json`.
This does not establish production requester coverage, customer-scale acceptance, live-operation
success or the deferred membership-change operation proof; P-227 remains open.

## Stage 7 fourth checkpoint: own-account membership obtainability

**Owner-approved scope; implemented and offline verified as P-231.** After preparation against `812286b`, the owner selected
“Approve the bounded checkpoint” for a separate saved assessment of whether a requester can obtain
membership, without changing genuine Self-Membership authorization or ordinary Add-readiness
answer. The owner subsequently selected “Implement approved checkpoint 4” to start implementation.

**Narrow correctness correction also approved:** the owner selected “Approve correction and continue”
after an offline regression exposed captured right-name metadata redefining Self-Membership as an
arbitrary GUID. Holder and requester interpretation, including the inactive discovery filter, must
use Microsoft's fixed Self-Membership identifier; retain the captured metadata as evidence rather than
rewriting it. Genuine permissions and ordinary Add readiness stay unchanged, and this does not
authorize changes to unrelated rights or activation of requester discovery.

- Support one captured ordinary user and one same-domain global security group, with qualified
  identities and domain context. Establish Self-Membership authorization directly or through one
  pre-existing explicit global-security-group membership, retaining relevant allows, denies and
  uncertainty in captured order; never use the proposed new membership to authorize its own creation.
- Assess addition of only the requester's own DN, not another account, replacement of the member
  list or removal. Validate applicable membership-operation prerequisites separately; missing required
  schema, identity or resource evidence remains Unknown, never defaulted to supported.
- Where membership is already proved, retain the existing route without inventing an Add. Where
  current membership is unknown, establish obtainability only if both possibilities are justified:
  already a member, or absent and a supported own-account Add is authorized. Keep current membership
  and ordinary Add readiness Unknown; an unresolved branch cannot become a proven path.
- Follow the resulting membership only through qualified existing memberships to the shared fixed
  Tier-0 targets, including a target group that is itself fixed. Do not transfer every group-held
  permission, infer account takeover or chain additional hypothetical changes; general member-write
  rights and unsupported requester routes remain outside this slice.
- A disabled account blocks the new operation proof without erasing permission evidence; an enabled
  flag does not prove authentication. Keep missing captured evidence, unsupported analysis, unresolved
  identities and work not performed distinct, preserve independently proven routes despite unrelated
  gaps, and emit no new NotReachable claim.
- Save original permissions, operation assumptions, membership witnesses and exact source generations
  for passive readback. Keep operation assessments separate from holder counts, distinguish the inferred operation from captured
  membership, qualify path length, and preserve the previous valid result on cancellation or failure.

Microsoft's [member validated-write rule](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1dea6a2c-a692-427f-8571-68a8a5c7b735)
and [modify constraints](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/76df255d-dc67-4c1f-adc6-1e5b60021304)
anchor the distinction between own-account permission and operation success. The two-case obtainability
inference is the approved product rule, not evidence that a missing member value proves absence or that
a live Add succeeded. Verification must be synthetic/offline, with deliberate-defect checks for each
new behavior and explicit rebuilds; original evidence, historical tests and validation artifacts remain
untouched. Requester discovery stays inactive, with no production budget, screen changes, live access,
optimization, commit or push authorized; P-227 and outstanding acceptance remain open.

Judgement format 34 and path-calculation version 3 implement this bounded checkpoint, including the
approved fixed-identifier correction, with unchanged production scheduling and passive readback.
All **5,128 offline tests pass**, all **523 focused cases pass under separately verified coverage**,
and all **70 new cases detect deliberate defects across 13 accepted variants**, with explicit rebuilds
and verified source restoration. Original evidence and validation artifacts remain preserved, including
the initially masked mutation check and the unsuccessful coverage-collector attempt; the final record is
`next/artifacts/stage7-own-account-validation/f881c28fc86e4e98b79301c0636b5e00/final-summary.json`.
This is not production requester coverage, customer-scale acceptance or proof of live-operation success;
further operation/path expansion requires a separately approved checkpoint.

## Stage 7 fifth checkpoint: own-account addition through ordinary Write Members

**Owner-approved scope; implemented and offline verified as P-233.** After reviewing the saved
`e48fca4` baseline, the owner selected “Approve bounded scope” for the next implementation checkpoint.
The owner subsequently selected “Implement approved checkpoint 5”, authorizing implementation without
activating production requester coverage or changing the other boundaries below.

**P-232 correction also approved:** after a raw-GENERIC_WRITE regression exposed the shared reader
expanding stored permission bits into authorization, the owner selected “Approve correction and continue”.
Preserve raw stored masks for permission interpretation, leave comparison/hashing normalization unchanged,
and verify affected consumers offline before accepting checkpoint 5; repair the separate malformed
callback fixture without weakening its expected uncertainty. Preserve failed runs and frozen evidence,
and stop again if a frozen expectation needs editing; no screen wording/layout or scheduling change is authorized.

- Support one captured ordinary user obtaining membership in one same-domain global security group
  through ordinary write access to `member`, followed only by qualified existing memberships to the
  authoritative fixed Tier-0 targets, including a target group that is itself fixed.
- Establish concrete requester authorization directly or through one proved, pre-existing explicit
  membership in a same-domain global security group. Evaluate applicable allows and denies together
  in captured order; do not transfer the holder's permission to every member without this check.
- Support member-specific and all-properties writes, plus class/property-set scopes where captured
  schema establishes that they cover `member`. Preserve original entries and scope evidence; neither
  a Full Control summary nor Self-Membership authorization substitutes for ordinary member-write proof.
- Assess adding only the requester's own distinguished name. This is the checkpoint's deliberate
  restriction, not a restriction inherent in ordinary Write Members; adding other accounts or groups
  remains later work, not a claim that those operations are impossible. Reuse P-231's identity,
  account-status, group, schema and verified-domain operation safeguards without relabeling its
  Self-Membership assessment.
- Retain a proved existing membership without inventing an Add. If current membership is unknown,
  establish obtainability only when both the already-present branch and the absent-with-supported-
  authorized-Add branch hold; current membership and ordinary Add readiness remain Unknown.
- Permit at most one hypothetical membership step. Never use the proposed membership to authorize
  its own creation, exercise another group-held permission, chain a further change or infer account
  takeover. Afterwards follow only qualified captured membership links, retaining the actual links
  and qualified shortest-proven length rather than inventing a new Tier-0 definition or depth limit.
- Keep missing captured evidence, unsupported analysis, unresolved identities and unrequested or
  unfinished work distinct. Unsupported authorization nesting, primary-group/SID-history routes,
  cross-domain/resource contexts and conditional or uninterpreted permission entries remain possible
  where relevant, not denied or safe; these limits do not remove previously supported membership paths.
- A disabled requester blocks the new operation proof without erasing permission evidence or proved
  existing membership; enabled status does not establish authentication. Failure of ordinary-write
  authorization does not invalidate an independently proved Self-Membership route, and unrelated gaps
  do not erase a proved route. Continue to emit Reachable or Unknown, not a new NotReachable claim.
- Save ordinary-write authorization separately from Self-Membership while reusing operation safeguards
  and membership continuation. Retain original permission references, membership witnesses, assumptions
  and exact Evidence/Derivation/Judgement generations; keep holder counts independent, readers passive
  and previous valid results intact on cancellation or failure. No backward compatibility is required,
  and historical evidence or generations must not be rewritten.

Verification must be synthetic/offline and cover permission separation, ordered denies, property scope,
unknown membership, self-authorization prevention, membership-only continuation, unchanged counts,
source mismatches and cancelled/failed publication. Every new behavior check must detect a deliberate
defect, with explicit rebuilds before mutations and after restoration; retain all original and new
validation artifacts. Requester discovery and host scheduling remain unchanged; no new production
budgets, live access, optimization, screen changes, commit or push are authorized. This is a calculation
and passive-readback building block, not production requester coverage or live-operation/customer-scale
acceptance; P-227 remains open.

Judgement format 35 and path-calculation version 4 implement this checkpoint, including P-232's
approved raw-mask correction without changing comparison normalization or historical layout hashes.
All **5,200 offline tests pass**, all **778 focused cases pass under verified coverage**, and all
**95 new or updated behavior cases detect deliberate defects across 11 accepted variants**, with
explicit rebuilds and verified restoration. Original artifacts, failed runs, the interrupted mutation
and the corrected masked proof check are retained with exact source/build provenance in
`next/artifacts/stage7-member-write-validation/ef9369e3a2db4e7285912e1fd3c71d75/final-summary.json`;
further operation/path expansion still requires a separately approved checkpoint.

## Stage 7 sixth checkpoint: obtained membership followed by requester DACL permission

**Owner-approved scope; implemented and offline verified as P-234.** After preparation
against `3fb945b`, the owner selected "Approve scope for next implementation session" for one supported
own-account membership-obtainability step followed by concrete requester `WRITE_DAC` authorization on
a same-domain fixed Tier-0 target. This approval records the supported-step and uncertainty boundaries;
the preparation session did not authorize implementation. The owner subsequently selected
"Implement approved checkpoint 6", explicitly authorizing implementation with the same boundaries.

- Support one captured ordinary user obtaining membership in one same-domain global security group
  through either the existing Self-Membership or ordinary Write Members proof, keeping those permissions
  separate. Reuse the identity, account-status, schema and verified-domain safeguards; authorize the
  membership using pre-change evidence only, directly or through the supported pre-existing explicit
  global-group membership, never using the proposed membership to authorize itself.
- Retain proved existing membership without inventing an Add or widening existing requester support.
  Where current membership is unknown, require both the already-present and absent-with-supported-
  authorized-Add branches; current membership and ordinary Add readiness remain Unknown.
- The terminal grant must name the obtained group and carry concrete `WRITE_DAC` applying to the
  authoritative classifier's fixed target in the same verified domain. No intervening nested-group
  permission route, second hypothetical membership, ownership transition, account takeover or onward
  operation is included; configuration/schema-partition authorization remains outside this slice.
- Evaluate the target's DACL for the user in a separate post-membership context, not as the group.
  The obtained group's SID participates in both allows and denies, without removing the user's other
  applicable identities or fabricating captured membership. Evaluate relevant entries in captured order,
  including denies for the user, obtained group, supported pre-existing groups and applicable broad
  identities; a later deny does not undo an already completed grant.
- Reassess trustee applicability after the membership change. Relevant unresolved nested-group,
  primary-group, SID-history, conditional or uninterpreted permission effects remain Unknown where
  they could change the answer, not excluded using the pre-change context. An earlier potentially
  applicable deny prevents a definite positive answer when its applicability cannot be settled.
- State the ordinary authenticated-context assumption with the obtained membership available for
  authorization. This is not a claim that existing sessions or tickets immediately acquire it, that
  authentication or replication convergence was proved, or that any live operation succeeded.
- Save a separate combined proof naming the requester, group, fixed target and membership-permission
  kind, original permission references, witnesses, assumptions and exact Evidence/Derivation/Judgement
  generations. Do not weaken captured-membership proofs, multiply holder counts by requesters or routes,
  activate discovery, or imply an administrator-maintained selection list.
- Keep missing evidence, unsupported analysis, unresolved identity/resource context and unrequested,
  cancelled or unfinished work distinct. Only a fully supported route contributes Reachable; otherwise
  preserve Unknown rather than NotReachable, without erasing independent proven routes or overstating
  shortest-proven length. Readers remain passive and failed/cancelled publication preserves the previous
  valid result; no backward compatibility is required and historical generations are not rewritten.

Microsoft's [ordered access-check rules](https://learn.microsoft.com/windows/win32/secauthz/how-dacls-control-access-to-an-object),
[SID applicability](https://learn.microsoft.com/windows/win32/secauthz/sid-attributes-in-an-access-token)
and [session/ticket membership behavior](https://learn.microsoft.com/troubleshoot/windows-client/group-policy/group-membership-changes-not-updating-over-some-vpn-connections#effects-on-the-user-security-context-and-access-control)
anchor these distinctions. Verification must be synthetic/offline, cover both membership mechanisms,
ordered and newly applicable denies, self-authorization prevention, uncertainty, unchanged counts,
source binding and publication safety, and mutation-test every new behavior with explicit rebuilds
before mutations and after restoration. Preserve original evidence, failed runs and validation records;
checkpoint 5's pre-commit provenance and saved document hashes remain historical, not updated for this
decision. No requester discovery, production host-scheduling changes, new budgets, screen changes,
optimization, live access, commit or push is authorized; P-227 remains open, and P-142/P-143 assets,
broader requester coverage, fuller paths, SEC-071 findings and product presentation remain later work.

Judgement format 36 and path-calculation version 5 implement this bounded checkpoint, including the
saved authorization-context assumption and passive proof validation, without changing production
requester scheduling. All **5,271 offline tests pass**, all **849 focused cases pass under verified
coverage**, and all **71 new behavior cases detect deliberate defects across 11 accepted variants**,
with explicit rebuilds and verified restoration. Original evidence, failed runs and mutation records
remain preserved with exact source/build provenance in
`next/artifacts/stage7-membership-dacl-validation/8c39670d898a4514b72c9d41437203fe/final-summary.json`.
This is not production requester coverage, customer-scale acceptance or proof of live-operation
success; further operation/path expansion requires separately approved scope.

## Stage 7 seventh checkpoint: offline requester selection for supported paths

**Owner-approved scope and implementation; implemented and focused-offline verified as P-240; full-suite verification remains open.** After preparation
against published `385e312` and review of the preserved P-227 failure, the owner selected
"Approve scope for next session" for permission-led selection of requester questions for the three
existing supported path families. This records the next bounded scope, not permission to implement
it during preparation, activate discovery in normal audits or claim Stage 7 complete.
The owner subsequently selected "Implement approved checkpoint 7", authorizing implementation
with the same boundaries; that authorization remains recorded when recovering an interrupted chat.

- Derive questions from captured permissions and the shared classifier's fixed Tier-0 targets,
  rather than every possible user/object pair or an administrator-maintained requester list.
  Cover existing requester `WRITE_DAC`, own-account membership followed by qualified existing
  memberships, and P-234's obtained-membership-to-requester-`WRITE_DAC` composition.
- Include relevant non-Tier-0 intermediate groups; do not require the group where a route begins
  to be Tier 0. Keep the existing ordinary-user, same-domain and direct/single-global-group requester
  authorization boundaries, including the existing qualified membership continuations; this adds
  selection, not new nested-group authorization, permission semantics or hypothetical operations.
- Selection identifies questions, not proven permissions or paths. Reuse the existing permission,
  operation and combined-proof evaluators, including pre-change authorization, post-membership
  ordered denies and both Self-Membership and ordinary Write Members mechanisms without merging them.
  Preserve Unknown current membership and ordinary Add readiness, independent holder counts,
  existing ownership findings and independently proven routes.
- Save the source reasons for selecting each question and the selection's coverage, bound to the
  exact Evidence, Derivation and Judgement generations and analysis versions. Keep missing captured
  evidence, unsupported analysis, unresolved identities/resource context and unrequested, cancelled
  or unfinished work distinct; broad identities remain explicitly unexpanded rather than absent.
  Neither an empty selection nor a completed supported scan establishes forest-wide requester
  coverage or NotReachable, and relevant uncertainty must not be discarded because no concrete
  requester could be identified.
- Exercise the selector only through synthetic/offline verification in this checkpoint. Both
  production hosts retain inactive requester discovery and unchanged scheduling, without a new
  budget, processing limit or customer-scale acceptance claim. This bounded selector does not
  settle the full production discovery scope or limitation presentation deferred under P-189b.
- Readers remain passive: verify saved questions, source provenance and proofs without discovering
  new requesters on reopening. Failed or cancelled publication must preserve the previous valid
  generation; historical evidence, validation summaries and their pre-commit provenance remain
  unchanged, with no migration or legacy-reading requirement.

Verification must cover all three route families, relevant groups outside Tier 0, applicable denies,
uncertainty, duplicate inputs, independent permission counts, source binding, passive reopening and
cancellation. Every new behavior check must detect a deliberate defect, with explicit rebuilds before
running mutated code and after restoration; retain failed runs and original artifacts. P-227 stays
open with cause unconfirmed: the preserved CI overlap failure is not replaced by local verification,
and neither its assertion nor its watchdog is weakened.

This checkpoint produces no screen changes or SEC-071 findings and does not activate requester
discovery, change budgets, add account-takeover claims, authorize live access or measurement/optimization
work, commit or push. Production requester coverage, further justified path compositions, P-142/P-143
asset coverage, canonical SEC-071 findings and path presentation/counts remain Stage 7 work, ahead of
P-235–P-239 and the broader rule rollout; implementation authorization covers only this bounded checkpoint.

Judgement format 37 and path-calculation version 6 implement this checkpoint with unchanged production
scheduling. All **908 focused cases pass under verified coverage**, including **59 new behavior cases**
that detect deliberate defects across **12 variants**, with explicit rebuilds and verified restoration.
The corrected full offline run passed **5,326 of 5,330 tests**: four unchanged layout checks timed out
under P-241, despite all 46 layout cases passing separately, so no clean full-suite or display-acceptance
claim is made. P-227 remains open independently of its local passing result, and this is not completed
Stage 7 or production requester coverage. Original evidence, failed runs and exact source/build
provenance are preserved in
`next/artifacts/stage7-requester-selection-validation/ffedb6f851754854a0f224d53cfdbfb7/final-summary.json`.

**Subsequent publication verification:** CI run 35157219659 for `9bb8423` completed successfully
with 5,330 tests. This later result does not explain or close P-241's local full-run timeouts or
P-227's earlier CI overlap failure; P-240's qualified full-suite verification remains open.
The handoff above remains a pre-publication record: its commit, publication flags, source hashes
and failed-run history must not be rewritten to describe the later push.

## Stage 7 eighth checkpoint: directory-registered enterprise CA targets

**Owner-approved scope and implementation; implemented and offline verified as P-142.** After preparation
against published `9bb8423`, the owner selected "Approve scope for next session" for the bounded
P-142 scope below. This records the scope, not authorization to implement during preparation;
the subsequent separate request "begin implementation" authorizes implementation with these same
boundaries, without authorizing live access, requester activation, budgets, screens, commit or push.

- Retain `dNSHostName` in future captures, including enterprise CA registrations and computer
  accounts, and retain CA registrations and host values in the source-bound derived inputs.
  The capture catalogue before version 8 omitted this field; reading the configuration partition does not
  capture every attribute. Do not rewrite or recapture historical evidence to supply missing values.
- Recognize `pKIEnrollmentService` registrations in the verified Enrollment Services container of
  the captured configuration partition. Add the registration and its uniquely matched captured
  computer account to the existing authoritative Tier-0 definition, not a separate CA target list.
  Retain the registration, recorded host value, matched identity and exact source generations as
  classification evidence; absent, conflicting or ambiguous host evidence remains unresolved.
  Do not use live DNS, server-name conventions or service-principal-name guesses as substitutes.
- Carry those targets through existing assessment admission and saved path inputs, retaining
  current permission checks, supported operations, independent holder counts and resource scope.
  Asset classification does not make controlling principals expected, suppress edges or change
  severity. A directory-registered CA is not proof of a running service; control of its registration
  is not automatically control of its host, certificate issuance or account takeover.
- Do not newly classify certificate templates or `NTAuthCertificates` in this checkpoint. AD FS
  remains declaration-only under `0099`; P-143 declarations are not included. These exclusions
  do not label unassessed assets safe or remove existing independently supported conclusions.
- Requester discovery remains inactive, with unchanged GUI/CLI scheduling and budgets. No new
  path composition, SEC-071 finding, screen wording/layout or summary count is included; those and
  production requester coverage remain Stage 7 work before P-235–P-239 and the broader rule rollout.
  There is no live access, recapture, optimization/measurement-harness work, commit or push approval.

Verification is synthetic/offline: capture-to-readback retention, correct container and class,
missing or duplicate host identities, shared-target integration, unchanged permission behavior and
counts, exact generation binding, passive reopening and cancellation. Every new behavior check must
detect a deliberate defect, with explicit rebuilds before mutated runs and after restoration;
focused coverage and full-suite results retain failures without weakening watchdogs or assertions.
P-227, P-240's qualified full-suite verification and P-241 remain open despite the later successful
published CI run; no customer-scale or outstanding display acceptance follows from this scope.

Capture catalogue 8, derivation format 15, judgement format 38 and Tier-0 policy/contract 2 implement
this checkpoint; path-calculation version 6 and requester-selection version 1 are unchanged.
All **5,390 offline tests pass**, and all **1,294 focused coverage cases pass**, with execution hits
for all **27 new test methods**. The **59 new cases**, three updated rejection checks and two
presentation-accounting checks have assertion-based negative controls across **10 rebuilt defect
variants**, with explicit rebuilds and verified restoration. The non-display catalogue records the
host field's analysis purpose without changing runtime sections, labels or layout.
Original evidence, historical checkpoints and failed runs remain preserved; the qualified handoff is
`next/artifacts/stage7-enterprise-ca-validation/37e2af93ddd741329736ca392d070b7f/final-summary.json`.
This is not completed Stage 7, production requester coverage, customer-scale or display acceptance,
and does not close P-227, P-240's qualified verification or P-241.

**Subsequent publication verification:** CI run 35174500509 for published `00a5e8f` passed
5,389 of 5,390 tests and failed P-227's capture-overlap assertion at line 72; the matching assertion
does not establish the same cause as earlier failures. The local 5,390-test pass remains a separate
result, and the handoff above keeps its original pre-publication provenance. CI metadata and
failed-step logs are retained under
`next/artifacts/stage7-enterprise-ca-validation/37e2af93ddd741329736ca392d070b7f/ci-35174500509/`.

## CLI and GUI judging parity

**Owner-approved requirement:** the same sealed evidence and analysis inputs must receive the same
judging behavior through the CLI and GUI. Both hosts must use Tier-0 discovery to select detailed
control assessment, while ordinary rules continue to examine every captured object; a host must not
silently select a different assessment scope. Host-specific presentation does not authorize different
security conclusions, and historical all-object test entry points are not the production CLI policy.

Stage 6's implemented, offline-verified slices are not acceptance of every capability or completion of
its outstanding controlled-evidence, customer-scale and display checks. This alignment does not enable
Self-Membership requester discovery: that separate scan remains inactive in both hosts, with its scope,
limitations and enablement deferred to Stage 7 rather than treated as working Tier-0 requester analysis.

## LAPS attribute-read findings: encrypted values

**Owner-approved wording and scope for P-162.** SEC-090 distinguishes permission to read a
password attribute from permission to decrypt its value, and neither is a claim that a password
was retrieved or a machine taken over. High severity, detection, finding identities, membership
paths and scope remain unchanged; no layout change, decryption assessment or rewrite of saved
findings is authorized, and corrected finding text is produced when judging runs again.

- Title: “A broad principal can read LAPS password attributes”.
- Encrypted-attribute explanation: “This attribute stores an encrypted LAPS password. Read
  permission allows retrieval of the encrypted value, if present; it does not by itself grant
  permission to decrypt it. This finding does not establish that this principal can obtain the
  local administrator password or take control of the machine.”
- Clear-text-attribute explanation: “This attribute stores a LAPS password in clear text. If a
  password value is present, reading it exposes the local administrator password and may enable
  local administrative access.”
- Opening of **Why it matters**: “A broad principal has read access to a LAPS password attribute.
  A clear-text value can expose the local administrator password; an encrypted value requires
  separate decryption permission. Read access alone is not proof of password retrieval or control
  of the machine.” The existing subsequent group-nesting explanation remains.
- In **About**, replace “it names can genuinely read the password” with “it names has permission
  to read the attribute. For encrypted values, decryption permission is separate and is not
  established by this rule.”
- In the finding's scope explanation and **What to do**, replace “rather than only the password”
  with “rather than only this LAPS attribute”.

## Enatel SSO object capture scope

**Owner-approved default and presentation, tracked as P-224.** New captures exclude
`enatelSSOAccountParameter`, `enatelUserManagedAuth` and `enatelSSOStorageV3` by default.
On the wizard's review page, an **Object classes** section below the domain list offers
**Include Enatel SSO metadata objects**, unchecked for each new audit and not saved as a setting.
Its help says: “Excluded by default to reduce capture volume. Excluded objects and their permissions
are not assessed.” The command line has the same default and an `--include-enatel-sso` option.
DNS exclusions remain unchanged, all other classes remain in scope, and inclusion does not add
credential attributes to the capture catalogue.

This is an explicit scope trade-off, not a claim that these objects are harmless or unused by all
rules: generic ownership and permission rules can examine them. Exclusions belong in LDAP requests,
not just the display; each saved run must record its actual class scope and disclose it on readback,
and differing choices must not appear as ordinary additions or deletions in a comparison.
Replace the review's “Nothing is being left out of this audit” with “No domains are being left out”
and show class exclusions separately. Existing captures must not be rewritten or relabelled using
the new default; the historical two-thirds observation is not a measured speedup for this change.
The existing no-compatibility decision (`0001`) still applies: an older evidence format is refused,
not migrated, and original files are preserved.

## Capture preflight: domains with no controller

**Owner-approved wording for P-213.** In the existing error area, report:
“No writable controller was found for: {domain names}. Each domain needs an exclusion attestation
before capture can start.” No layout change was approved; saved preflight output must retain those
declared domains separately from any valid exclusion attestations, without claiming they answered.

## Capture connection failures after authentication

**Owner-approved correction and wording for P-214.** Once authentication succeeds, a failed
RootDSE read is an operation failure, not a refusal of connection protection; do not try weaker
protection, and do not return a usable capture connection without the required capabilities.
Use the existing error displays without layout changes: “Connected to {controller} using
{protection level}, but could not read its directory capabilities (RootDSE). This connection cannot
be used for capture. {error details}” The details retain the returned diagnostic message and,
when available, the LDAP result name and number, such as “LDAP result: Busy (51)”.
Classify actual response codes rather than treating every directory error as a security refusal;
existing retry/failover policies and the explicit allowance for unprotected connections are unchanged.

## Capture stops after a domain exhausts recovery

**Owner-approved correction and log wording for P-215.** Existing retries and next-controller
attempts run before a domain failure ends capture. The first terminal domain failure that triggers
shutdown remains the recorded cause; cancel active domain reads, prevent queued reads from starting,
and await connection and writer cleanup rather than abandoning work or sealing incomplete evidence.
An internally stopped domain must not turn the failed run into an operator cancellation; its log
says “partition stopped because another domain failed”. No layout change or new timeout is approved;
cancellation remains cooperative, and the LDAP abort race and pre-seal cancellation remain separate.

## Capture cancellation at publication

**Owner-approved correction and saved wording for P-216.** Honor cancellation during sealing
preparation, including cancellation from the “sealing the bundle” log callback, before one final
publication boundary. If cancellation wins, save: “The run was stopped while sealing the bundle;
no bundle was published.” If publication wins, later cancellation must not relabel completed
evidence as cancelled. No abandoned work may continue modifying or publishing evidence after a
cancelled return, and genuine sealing failures and safe cleanup must be preserved; no layout or
other wording change is approved.
The evidence-publication correction is implemented; the remaining CLI/screen cancelled-versus-ended
status correction is explicitly deferred under the priority decision above.

## SYSVOL acquisition must not hold a run indefinitely

**Owner-approved requirements, 2026-09-13.** A production capture reached “reading the policy
share” and showed no visible disk changes for roughly 1–2 hours before manual abortion; the
blocked operation has not been identified. SYSVOL acquisition must log and flush the start and
outcome of individual operations, naming the GPO, UNC path, operation, elapsed time and actual
progress counts. A cancellation token or a timed-out wait around synchronous SMB work is not
containment: abandoned work must not retain access to evidence persistence, supply late accepted
results, or accumulate without bound.

The owner selected **30 seconds without progress on an individual SMB operation** as a provisional
limit, not a production-measured default. On timeout, retain trustworthy completed evidence,
explicitly mark the affected policy incomplete (or unreadable if nothing usable was acquired),
abandon its remaining operations and **move to the next GPO**. An incomplete enumeration must not
mean an empty or complete listing, and database-integrity failures must still prevent sealing.
Implementation and offline verification are tracked as `P-221`; this does not authorize live access
or claim that the original production stall's cause is established.

## How judging works

**Release-run feedback changes the immediate priority.** The owner's lab investigation of
`ad.lab-20260908-062400` reported judging completing in 222 seconds for 8,407 objects, with a 654 MB
judgement store and 27 findings. The apparent hang was slow, silent judging after Evidence sealed,
not proof of a stuck worker. These are lab-reported observations, not a measurement rerun on this
development machine; comparisons with the older 13-second run include substantial changes in stored
control evidence and require profiling before assigning cost to individual additions or rules.

The owner authorized visible progress through all available audit phases and approved a pinned phase
panel, real counters, elapsed/last-update ages and separate outcomes. The
New Audit progress correction
records the implementation and limits. Performance/storage profiling and logging hardening remain
separate work. Profiling can use sealed copies and representative synthetic data without contacting
a directory; production-shaped synthetic results alone do not establish customer acceptance. Preserve
original lab runs and historical artifacts. The reported clean-clone `ProsePathCitationTests` failure
on local ignored coverage references remains a separate documentation-portability issue; a local pass
where those artifacts exist does not resolve it. No publication or live work is authorized here.
The progress correction built successfully and passed 4,372 offline tests (four stage-status tests
excluded) plus 179 targeted coverage tests. Its detailed verification record is in the linked New Audit
page. It adds no production budget and makes no improvement claim for the reported judging runtime.

Decided, built and measured — see layers/judgement/.

- **One pass over the bundle, not one per rule.** Every object is streamed once and offered to every
  scheduled rule while it is in hand, so judging forty rules costs the same read as judging one.
- **A rule judges one object and nothing else.** No forest, no sibling lookup, no second pass, so a
  rule cannot quietly acquire an input it never declared.
- **A rule declares the data it reads, or the build fails** (`0083`).
- **Atomic per rule, not per run.** A rule that throws loses only itself; its partial findings are
  discarded, because a partial verdict would read as a complete one.
- **Findings live outside the seal** (`0085`), in a store that is disposable and rebuildable.

**What "inside a group" means, and it is an authorization question rather than a directory one.**
Owner's decisions, 2026-09-11. A distribution group nested inside a security group *is* a member of
it and is reported as one, but nothing beneath it is: Microsoft is explicit that an account nested
through a distribution group does not receive the enclosing group's SID in its access token, so
following that hop would name principals who hold nothing. A group whose `groupType` the capture
never read is **not** treated as a distribution group — the route is followed, because refusing it
would hide access that exists, and the answer is marked as one the product cannot vouch for, so a
rule refuses rather than reporting the object clean. A group asked about by a SID it carried before
a migration expands to its real members, because `sIDHistory` is a second identity the principal
answers to rather than a group it belongs to. See `P-165` and `P-166`.

**When a domain was excluded or unread, only principals from that domain lose their protection
answer.** Owner's decision, 2026-09-11, for `P-163`. Making the whole forest's answers unknown
because one domain was deliberately left out would stop ownership findings being reported anywhere,
and judging discards the findings of an object with unresolved inputs. Membership reaching *into* an
unread domain is already covered, because a member nobody captured does not resolve and is recorded
as an unresolved trustee, which qualifies the answer on its own.

**The acknowledged rule-input gap:** rules that depend on cross-object facts need persisted,
Evidence-bound Derivation products and typed missing/degraded input handling. The accepted correction
order is recorded in [`docs/next/WORKFLOW.md`](next/WORKFLOW.md); it is no longer treated as an unbounded
architectural question.

**Stage 6 has started, not finished.** Judging stores WRITE_DAC/WRITE_OWNER, bounded
group-membership control, password-reset permission, key-credential write permission, bounded replication permissions and bounded existing-owner control, with full-control permission summaries and object-first and named-holder-first
views in the object screen.
**Bounded effective-member attribution is implemented and synthetically verified.** The owner accepted
the proposal, exact wording and 0102 timing clarification, then requested implementation. Derivation
schema 11 stores source-linked membership inputs; judgement schema 24/control engine 8 stores budgeted
members, unresolved links and representative independent routes, with resource applicability beneath
existing group-held permissions without multiplying their counts. Member
attribution is not a concrete requester assessment. Full-control supports, independent existing-owner
control and Unknown/uncounted owner transitions retain their current behavior. Both production hosts
remain without an approved expansion budget; discovery, live access and retrying the
cancelled stage-status check are not authorized. The owner subsequently authorized documentation
closeout, commit and push of this completed slice; that is not standing publication authorization.
Synthetic verification and customer-shaped measurement
must be reported separately from production-budget approval and final Stage 6 acceptance.
Final offline verification passed 4,355/4,355 tests with the four stage-status tests explicitly excluded;
targeted coverage passed 799/799, and the solution build succeeded. The
implementation record
records the final artifacts and outstanding acceptance boundaries. No production expansion budget is approved.
General membership writes and own-account-only Self-Membership candidates are separate; concrete
requester answers are not implied by those candidates. Historical schema-16 Self-Membership
candidates remain Unknown, and no general member capabilities are expanded.
The owner-to-DACL transition remains unknown and uncounted. Current judgement schema 27 stores this
product, the bounded Self-Membership requester assessments introduced in schema 17, and discovery
coverage introduced in schema 18; schema 19/control engine 3 introduced reset permission, and
schema 20/control engine 4 added key-credential write permission and the property-set evidence safeguard;
schema 21/control engine 5 added the two replication capabilities on captured naming-context roots;
schema 22/control engine 6 added existing-owner assessments and replay-validated ownership proof;
schema 23/control engine 7 adds bounded full-control summaries with separate source proof and counting links;
schema 24/control engine 8 adds explicitly budgeted member attribution, requiring current Derivation inputs;
principal catalogue version 2 includes the verified BUILTIN domain-scope correction, P-150.
Schema 25 implements the approved shared permission-proof storage,
with unchanged control engine, catalogue and input formats. Complete lab public-model comparison passes,
and the database is 20.8% smaller including indexes and references. Exhaustive export allocation
increased; no runtime or memory improvement is claimed. Production-shaped validation remains outstanding,
and this work authorizes no production expansion budget or publication.

**Scoped ownership during audits is implemented; explicit object requests remain pending.**
The owner approved **core Tier 0 plus its identified controllers and dependencies** as the default
scope for detailed ownership-takeover assessment during an audit. Other objects remain unassessed
until the pending explicit single-object workflow is implemented; that workflow will use the existing
captured evidence rather than contact the directory.
The scope must be determined automatically; this slice adds no user-maintained importance or target
list. Importance follows control relationships toward Tier 0, not everything an administrator owns
or manages. Expected administrative authority remains separate from target importance.

**One Tier-0 definition:** the owner explicitly requires reuse of the existing authoritative
[Tier-0 policy](decisions/0006-tier-0-and-expected-admin-are-separate-sets.md) and its shared
classification implementation. Ownership assessment must not introduce another Tier-0 list or
copy the definition into its own selector. Any gap in evidence-backed classification must be
resolved centrally against that policy. Additional controller/dependency inclusion is an assessment
scope reason, not a second Tier-0 definition or a change to expected-admin policy.

**Shared across the application, not owned by ownership assessment:** the owner agreed that target
importance must come from one shared, evidence-backed Tier-0 model, reusable by ownership assessment,
later path analysis and other features asking the same question. Reuse the broader design's
distinctions between core targets, effective security-group membership, qualifying established direct
control and longer or conditional reachability. Ownership consumes those shared facts and decides
which targets receive detailed assessment; it does not create a parallel definition of importance.
Being included because of a possible route or dependency does not establish that an object is Tier 0.
These answers remain separate from protection, accepted ownership, expected administration and rule
severity; they must not collapse into a universal privileged-or-important flag.

The broader judgement design
already describes these distinctions, but is not a completed shared classifier. Its outdated seed
exclusions must not override the authoritative Tier-0 policy. Existing membership and control evidence
are reusable inputs, not proof that the combined classification is implemented. This agreement settles
the shared direction, not approval of the earlier identifier-only implementation proposal, unresolved
classification semantics or UI changes; revise the bounded implementation proposal against this model
before editing runtime behavior. It does not require building the complete path engine first.

The [revised shared-contract proposal](next/SPEC-stage-6-control-edges.md#15-proposed-shared-tier-0-and-ownership-contracts)
defines classification and relevance separately, their evidence/version bindings, ownership assessment
states and target-specific immutable publication. Its first implementation slice is central policy
reconciliation, shared contracts, supported evidence adapters and offline tests; audit selection,
persisted-format changes, object execution and UI integration were later work at that checkpoint. The owner explicitly
approved that bounded implementation slice, including the 0006/0099 reconciliation, under
[0112](decisions/0112-shared-tier-0-classification-and-ownership-contracts.md). This is implementation
approval for the shared foundation, not approval to activate scoped audits or change the UI.

**The bounded shared foundation is implemented.** Catalogue 3 corrects the canonical Tier-0 identifier
predicate without changing expectedness or owner acceptance. The shared adapter qualifies captured
core identities and supplied same-domain membership witnesses, retaining independent evidence and
explicitly incomplete coverage. It does not yet classify all assets, expand membership or qualify
operational direct control/dependencies. Shared directed relations and ownership result/binding
contracts are built and now consumed by the schema-26 audit integration below. The
implementation record
records that foundation checkpoint; its catalogue-2 compatibility does not override the current schema-version policy.

**The offline selector is implemented as a library** under
[0113](decisions/0113-automatic-ownership-scope-follows-shared-relations.md). It consumes the shared
classifications and follows incoming captured controller relationships, retaining conditional links,
alternative reasons and explicit incomplete results on cancellation. It blocks ambiguous identities,
handles cycles without repeating target visits, and keeps selector version 1 separate from the
classification version. The selector implementation record
states the supported inputs and validation. The selector-only slice added no membership expansion or
production limit; the subsequent integration now uses it during judging.

**Audit integration and status-only presentation are implemented** under
[0114](decisions/0114-scoped-ownership-assessment-during-judging.md): retain basic permissions and the
single rule pass, select ownership scope, assess selected targets, persist coverage and then publish.
The approved change uses schema 26/control engine 9 and requires re-judging older schema generations
for current readback without rewriting those older files. The owner approved explicit assessed,
not-assessed and unavailable-input status wording plus the two scope/assessment progress labels.
No on-demand action button, live work, production expansion budget or performance claim is included.
The schema-26 implementation record
describes proof-preserving staging, readback validation and the remaining acceptance limits. Shared
classification remains partial: incomplete scope is visible, never a declaration that unassessed
objects are safe. Subsequent single-run local diagnosis and read-only storage assessment are recorded
in the proposed bounded proof-storage redesign and validation plan.
They establish diagnostic costs, not a controlled speedup, guaranteed storage saving or production
acceptance. The owner requested this plan before further code changes. Its recommended first slice
shares exact repeated descriptions and complete membership explanations without narrowing basic
auditing or changing its answers. The owner then explicitly approved S1 and exactly one before/one
after lab judging execution under [0115](decisions/0115-share-judgement-explanations-and-membership-proof.md).
S1 is implemented locally as schema 27 and both approved passes are complete. The paired comparison
preserved the checked proof/products and reduced the new database by 10.51%, but measured elapsed time
rose 9.22% and cumulative allocation rose 20.47%. **Performance acceptance is on hold; this is not a
speed improvement or production acceptance.** The candidate and both runs are retained for review,
with no additional timed judging run authorized. Transaction batching,
validation-lifetime changes, graph-memory work and production-scale measurements remain separate work.

This changes the expensive hypothetical owner-transition work, not the existing current-owner
findings or the underlying WRITE_OWNER, WRITE_DAC and full-control evidence. Unassessed objects must
say that they were not assessed automatically, never appear safe. Unknown relevance, unsupported
dependencies and incomplete traversal must retain explicit coverage limitations. This is not approval
to build or claim a complete Tier-0 path engine as a prerequisite to the bounded ownership change.
The audit and object request must share one evaluator, retain alternative relationships and unresolved
prerequisites, and persist generation-bound results rather than recomputing silently when a page opens.
An object request is offline analysis, not a fresh directory observation, and must not rewrite sealed
Evidence or an already-published Judgement generation.

The ownership assignment/server-behavior verification gate remains open: requesting analysis cannot
turn missing evidence into a proven takeover. New audits use scoped assessment. Explicit single-object
execution and its separate target-specific publication remain unimplemented. The status-only UI
changes are approved and implemented; an on-demand action and any further wording/layout changes
retain their separate approval boundary.
No live access, recapture, production expansion budget, commit or push is authorized.

**Owner-confirmed direction: Tier-0-driven detailed assessment.**
The owner clarified that captured owners and permissions already exist in Evidence; asking to
"preserve capture" must not be presented as new work or a reason to build another complete permission
copy. An unrelated ordinary account such as `jimmy.strand` needs those captured facts and applicable
ordinary rule checks, not automatic detailed control/full-control or hypothetical ownership assessment.
Those detailed questions become relevant when discovery working backward from Tier-0 assets reaches
the account, or through an explicit investigation. Ownership is one possible control mechanism along
a route, not a separate justification for deeply assessing the whole forest.

Build the minimal shared path-discovery mechanism and use it to drive assessment admission in the
same slice. Use the existing authoritative Tier-0 definition, captured owner/ACL facts and source-bound
membership inputs; do not require an already-expanded forest-wide control store to discover scope.
Possible/conditional relationships can justify inspection before takeover is proven, avoiding a
circular dependency. Retain uncertainty and independent reasons, and do not label unreached objects
safe when coverage is incomplete. Full path visualization, ranking, remediation and all-path enumeration
are not prerequisites. Ordinary audit findings remain separate from scoped detailed-control products.

The owner requested that this be recorded with an implementation plan for a new session. The
[Tier-0-driven assessment plan](next/PLAN-tier-0-driven-assessment.md) records the pipeline replacement,
contract/read-count consequences, ordinary-versus-reached account acceptance cases, approval gates and
preservation/measurement limits. This is a broader behavior change than 0114's ownership-only gating
or 0115's storage sharing. Exact new contracts and UI wording/layout must follow the repository's
approval process; no further timed runs or new harnesses are authorized.

The concrete contract is accepted as
[0116](decisions/0116-discovery-first-assessment-admission.md). It settles four points the plan left
open: broad principals are recorded as one explicit unresolved candidate rather than expanded into
individual accounts; Judgement schema 28 is required because control-edge counts change meaning from
forest-wide to assessed-scope while their shape does not; the added scope wording is approved in
substance with its exact rendering confirmed before the Shell edit; and discovery retains the
controller/target route it already computes instead of discarding it after admission.

**As of 2026-09-10 this is built and the shell uses it.** `JudgingRun.JudgeWithTier0Discovery` runs
the gated pipeline and is what the audit screen calls; `JudgingRun.Judge` is retained for callers
needing the unscoped contract. The control-edges panel states that its counts cover the objects
discovery reached rather than the whole forest, and says so only for a judgement that was actually
scoped - schema 29 records which kind a stored product is, because the two are otherwise
indistinguishable and a reader would take the first for the second.

### Tier-0 discovery has no work ceiling — decided 2026-09-12

**The owner's decision:** *"why does it stop at a budget is my question. it shouldnt have one, if we
are building an app that is suppose to determine something and we have to stop arbitrarily then we
built it wrong."* Tier-0 discovery now runs until it has read what was captured. **Cancellation is
the only stop**, and it is an honest one: a scan the operator stopped is a fact about the run, where
a constant in the source is not.

`Tier0DiscoveryBudget` and its three `*BudgetExceeded` reasons are deleted rather than defaulted to a
large number. The ceiling that existed was the laboratory bound - 1,000,000 objects against a
recorded production shape of roughly 347,000, so it never bound anything in either forest. With no
ceiling, and cancellation throwing rather than returning, a scan can no longer finish incomplete:
the `ProcessingStopped` verdict and the corresponding `ProcessingIncomplete` mapping go with it,
under the standing rule that a reason the scanner cannot emit tells a reader the product looks for
something it never looks for.

**What replaces it on screen, approved verbatim:** `Finding what can control Tier 0 — 214,000
objects, 3 min 41 sec`. **No progress bar and no time remaining.** An unbounded scan has no endpoint
to forecast from, and a wrong estimate on a screen an auditor trusts is worse than no estimate. The
cost is accepted: at minute seven the operator knows it has taken seven minutes, not how many remain.

### Permissions mirrors the directory; Findings carries the judgement — decided 2026-09-12

**The owner's rule, stated at the screen and governing more than the case that prompted it:**
*"permissions on this screen should 100% mirror what is in AD. Findings is where we identify issues
and risk."*

**This is a separation of two jobs that are easy to blur.** The Permissions and Control-edges views
answer *what does the directory actually say*, and they answer it completely, including the parts
Microsoft shipped and nobody chose. Nothing is suppressed there for being common, routine or
uninteresting, because an operator checking what a principal can do needs the directory's own answer
rather than this product's opinion of which parts are worth mentioning. **A permission hidden because
it is ordinary is a permission the operator will not find when it stops being ordinary.**

Risk, ranking, thresholds and advice belong to Findings, where a rule says why something matters and
what to do about it. That is the place to argue an empty Account Operators is less urgent than a
populated one. Doing the same thing by hiding rows on the Permissions screen would make the two
views disagree about the same directory, which is the defect this product keeps finding in others.

### A true permission is reported, even when Microsoft shipped it — decided 2026-09-12

**The owner's decision, made at the screen.** Opening `CN=Cert Publishers,CN=Users,DC=ad,DC=lab`
showed BUILTIN\Account Operators holding **Full control**, and his answer was: *"now that i know this
is a permission then i have no issue with it showing up here, its the truth so it should show up."*

**This settles the acceptance question P-145 exists to ask.** Account Operators accounts for 15 of
the 29 unexpected control rows in the laboratory forest — just over half — and holds them in every
forest Microsoft has ever shipped, because they are the default ACL rather than anything an
administrator did. The question was whether a stock default dominating the screen means the
classification or presentation model is wrong. It does not: **the permission is real, the group can
genuinely rewrite that object, and a tool that hid it because it is common would be hiding a true
fact about the customer's directory.**

**What this does not license.** It is not a ruling that volume never matters, and it is not
permission to let a real finding become unfindable. The same laboratory run put a genuinely
forest-specific result — a `ph.ad.lab` principal, and `ph.ad.lab` Domain Admins, both holding
WRITE_DAC on the **`ba.ad.lab` domain root** — among those same rows. Cross-domain control of another
domain's root is the kind of thing an operator opens the product to find, and it must stay findable.
The owner accepted the current visibility on the basis that sorting and filtering handle it.

**The empty-group observation stands separately.** Account Operators is empty in all three
laboratory domains, with a *complete* membership summary rather than an unread one, so those fifteen
rows are a latent exposure rather than an active one. That distinction is worth surfacing and is
recorded in the punch list; it is not a reason to suppress anything, because anyone who can add a
member to that group inherits every one of those capabilities at once. **Empty, populated and
membership-unknown are three states, not two**, and nothing may collapse the third into the first.

### Self-membership requester discovery is deferred to Stage 7 — decided 2026-09-12

**Two separate scans were being discussed as one, and only one of them changed.** Tier-0 discovery
starts *at* Tier 0 and walks outward; self-membership discovery starts at *every* group in every
domain and asks who holds the "Add/Remove self as member" right on it. The second is **not** Tier-0
scoped - `JudgingRun` observes it for every streamed object, filtered only to groups - and it is
**inactive in both hosts**, because for that scan a null budget means the scan never starts.

Its budget therefore stays, along with `ProductionBudgetNotConfigured`, which is a true statement
about the product today. **Two questions are deferred rather than answered now:** whether the scan
should be forest-wide or scoped to Tier 0 plus identified controllers, and where its stated
limitations - nested groups not followed, Everyone/Authenticated Users not expanded, computer
accounts not treated as requesters - should surface. The owner's reasoning: both are the same
question as "path to Tier 0", and answering them before the path work exists would mean deciding
twice, the second time with better information.

The argument against Tier-0 scoping, recorded so it need not be rediscovered: **the first hop of an
escalation chain is never a Tier-0 group.** A self-membership right on an unremarkable group matters
because of what that group can reach, which is not knowable until chained-path analysis reads it.

Decision [0117](decisions/0117-naming-context-roots-are-tier-0-assets.md) was accepted alongside it.
A naming-context root holds no SID, so no controller route can reach it, and replication rights are
granted *on the root* — which on a domain root is every credential in the domain. Discovery-first as
originally written would have reported every partition root as not assessed automatically, in every
forest, permanently. Roots are now Tier-0 seeds on the strength of what they are. What a permission on
one *means* still differs by partition: the configuration and schema partitions hold no credential
material, and `ReplicationControlDeriver` already keeps that distinction.

**Assessment admission remains separate from paths.** `OwnershipScopeSelector` performs a backward
walk from Tier-0 seeds and produces an admission decision — `Included`, `OutsideComputedScope` or
`Undetermined` — not a route. Its retained relationships preserve that decision without becoming
completed control steps. The separate [bounded Stage 7 calculation](#stage-7-second-checkpoint-first-bounded-path-calculation)
now consumes qualified saved witnesses; it adds no path presentation, ranking, remediation or
all-path enumeration, and none of those become prerequisites to the admission work.

At the catalogue-2 checkpoint, re-judging alone obtained that correction. The current member-attribution
product requires current Derivation inputs: re-derive and re-judge an isolated copy, without re-capture.
The judgement-store document
records the implementation and before/after lab checks. P-145's expectedness and visibility acceptance
has since passed, as recorded above; separate capability-specific laboratory gates and member-attribution
scale measurements are not discharged by that acceptance. The
membership slice
has automated coverage, an isolated offline comparison and an
isolated live Self-Membership measurement.
The live direct/group-held tests and fresh readback passed. Those measurements did not include
concrete requester evaluation and do not accept the schema-17 implementation below. The new bounded
member-attribution product has separate synthetic verification; it does not widen requester semantics.
The comparison preserved all 65,084 existing primitives and added 10,776 established general
membership writes plus 10,761 unknown self-membership candidates. Re-judge schema-15 results to
obtain it; this does not accept the whole stage-6 proposal or replace the historical baseline.

**Password-reset control is an existing current-build requirement, not a new feature proposal.**
After the R8 checkpoint, the owner clarified: "we also have the stage 6 documentation which is for
this build", then said "begin" to the preparation described against that specification. Start from
`CanResetPassword` in the [Stage 6 catalogue](next/SPEC-stage-6-control-edges.md#5-the-edge-catalogue-for-stage-6),
the judgement-half requirements and accepted decisions. The predecessor banner on SEC-003 does not
make those current-build requirements historical. Identify the unimplemented capability, reusable
code and genuinely unresolved details; do not ask the owner to restate the requirement. This
preparation does not itself approve new UI wording/layout, a reset operation, discovery enablement,
further performance tuning or a commit/push. A stored password-reset capability and a security
finding about unexpected reset authority are separate deliverables.
The bounded implementation preparation
records the implementation path, versioning, verification cases and approved presentation.
The owner subsequently selected **"Approve the capability-first implementation and wording"**.
That approves this bounded stored-capability slice, the existing-table label "Password-reset
permission" and the permission-only/no-tested-sign-in caveat. It does not add a security finding,
member expansion, live directory operation, discovery budget or final Stage 6 acceptance.

**The approved password-reset capability was introduced in schema 19/control engine 3 and is retained
in current schema 22/control engine 6.** Normal
judging evaluates applicable captured reset rights and stores `CanResetPassword` as `CredentialExposure`,
independently of the inactive Self-Membership discovery budget. The existing table shows
"Password-reset permission" and keeps evaluation, expectedness and supporting evidence separate.
This is named-holder permission evidence, not a tested reset, complete requester-token evaluation,
sign-in prediction or SEC-003-style finding. Re-judge sealed evidence to obtain it; no re-capture,
Evidence/Derivation schema change or historical-result rewrite is needed. Validation and limits
are recorded in the linked implementation record; Stage 6 acceptance remains open.

**The key-credential write slice and wording are explicitly approved.** After reviewing the bounded
recommendation, the owner selected **"Approve the bounded implementation and wording"**.
`CanWriteKeyCredentialLink` is an existing current-build Stage 6 requirement, not a new feature
proposal. Schema 20/control engine 4 stores it as `CredentialExposure` and the existing table says
**"Key-credential write permission"**. It evaluates property writes, not the separate validated-write
route, and does not claim a tested write, sign-in, account takeover or completed path to Tier 0.
The implementation record
owns the exact boundary, reproduced defects and validation. No layout, capture/Derivation schema,
finding, discovery budget, performance tuning, commit or push is part of this approval. The separate
password-reset security finding and final Stage 6/P-145 acceptance remain outstanding.

The owner subsequently requested documentation review, a commit/push of this completed slice and a
new-session handoff. That is separate publication authorization, not standing permission to publish
future work.
The next recommended session was bounded replication preparation. The owner subsequently approved
the concrete implementation, wording and grouping ("i approve"), then requested "implement it".

**Replication permissions are stored conclusions for future rules, not new security findings.**
Capture already records the facts. This Stage 6 slice evaluates those facts into
`CanReplicateSecretDomainData` and `CanReplicateFilteredAttributes` as `ReplicationControl`, with
original entries, exact partition roots, component-right checks and uncertainty. Both existing views
show the approved **"Secret-data replication permission"** and **"Filtered-attribute replication
permission"** labels, with non-collapsing holder/root groups limited to the current page. DC holders
are not suppressed or granted an expectedness exemption. Missing/conflicting DC classification
evidence remains unconfirmed. Configuration/Schema scope is explicit; non-domain servicing contexts
remain unverified under P-90, except descriptor-native SYSTEM and NULL-DACL Everyone evidence.
The implementation record
owns validation and limits. This does not perform replication, extract credentials, establish takeover
or complete a path to Tier 0. Separate rules/findings and final Stage 6 acceptance remain outstanding.

**Preserved replication checkpoint:** the full offline suite passed **4,116/4,116**,
the solution builds, and the final targeted coverage selection passed **653/653**, including the
last BUILTIN scope correction. The earlier cancelled coverage attempt is preserved, not counted as
successful. The next recommended bounded session was **ownership-control preparation**, starting from
the existing requirements and accepted decisions, with explicit approval before the next implementation
or live laboratory work. The implementation record above owns the report, warnings and remaining gates.

**The bounded ownership implementation and wording are explicitly approved.** The owner selected
"Approve the bounded implementation and wording; offline only", then requested "implement it".
Schema 22/control engine 6 adds `IsOwnerAndCanRewriteDacl`, shown as **Existing-owner permission
control**, and records the missing steps behind **Owner-change permission control — not verified;
not counted**. Accepted owners and proven-deleted owners produce no ownership edge; incomplete
owner acceptance stays unanswered. Both viewing directions consume the same stored proof.
`CanSetOwner` stays independent and the AD DS owner-transition gate remains Unknown and uncounted.
The shared checks distinguish ordered OWNER RIGHTS permissions, complete class ancestry and missing
serving-DC behavior. No behavior baseline is inferred from a machine name or a heuristic alone.
SEC-031/032 are now version 3 and SEC-060 version 2; rule identities and severities are unchanged.
The ownership implementation record
owns verification and limitations. This approval includes focused shared-check corrections, not live
operations, discovery enablement, member expansion, new findings, final Stage 6 acceptance or publication.

**Ownership is at a verified offline checkpoint:** the full suite passed **4,182/4,182**, the solution
build succeeded, and the targeted coverage selection passed **623/623**. The linked implementation
record owns the saved report, line observations and closeout checks. Live owner-write/SDProp gates and
normal laptop/monitor checks remain outstanding; this is not final Stage 6 acceptance.

**Publication authorization:** the owner subsequently requested "ensure docs are update then commit
and push and give new session handoff". This authorizes publication of the completed replication and
ownership slices and their reviewed documentation/instruction changes, not standing permission to
publish future work. Local ignored coverage outputs and historical evidence remain untouched.

**Bounded full-control aggregation (`HasFullControl`) is implemented after explicit approval.**
The owner requested "implement it" after the recommendation, then "continue". Schema 23/control
engine 7 shows **Full-control permissions** only as a permission-summary assessment, not a new
primitive or an executed operation. All thirteen specific mapped rights must survive ordered
evaluation; raw generic bits are not expanded into grants, and unresolved scoped denies remain Unknown.
One or several grants can establish one counted summary. Supporting permissions and alternative
routes remain stored and visible, without being counted again. A broken or Unknown summary does
not suppress surviving permissions. Existing-owner control remains independent; owner-change
control remains Unknown and uncounted. Principal catalogue 2 is unchanged.
The implementation record
owns the 4,305/4,305 offline suite, successful build, 796/796 targeted coverage, proof-integrity
corrections and remaining gates. Historical tests, hashes and measurement reports are preserved.
No live access, discovery enablement, member expansion, new findings, Stage 7 paths, final Stage 6
acceptance, commit or push was included in the implementation approval. The owner subsequently
requested "commit and push then state next step", authorizing publication of this completed slice
only. The next recommended bounded session is **effective-member expansion preparation**, preserving
group-held counts and captured route evidence, with approval before implementation. The linked
checkpoint owns that boundary. Laptop/monitor checks remain normal outstanding verification.

**The bounded requester design was introduced in judgement schema 17 and is retained in schema 23.** The owner answered "continue then"
after the plain-language explanation. [Decision 0111](decisions/0111-bounded-self-membership-requesters.md)
limits it to direct user grants and one explicit same-domain global-security-
group membership. Requester assessments are stored separately from counted holder edges, with
ordered deny evaluation, an own-account constraint and separate operation readiness. Missing inputs
and unsupported routes remain unknown; the live measurements do not promote historical results.
Explicit request batches are persisted and shown object-first and requester-first without increasing
the named-holder count when supplied to the judging library. **Both hosts now reach the shared
automatic scheduler, but pass no discovery budget**, so ordinary re-judging still schedules no
requester assessments. Explicit batches remain a library input, not an administrator-maintained
selection list or a production scheduling workaround. The authorization
correction retains earlier uncertainty when it could change the ordered result and resolves SELF
to the captured target group's identity and membership, not to the requester. R5 persistence safety
is corrected: malformed stored requester records and mismatched holder references produce a
controlled read failure, including through the Shell adapter, rather than empty or partial answers.
R4 Shell readback safety is also corrected: failed reads and selection changes clear old answers,
and control/requester results from different judging runs are withheld rather than combined.
Requester-grid sizing and the approved R7 selected-answer presentation are implemented and
regression-tested. R8 reconciles the delivered state, not final feature acceptance. Production
enablement and real-product laptop/monitor validation remain outstanding; see the
review status.
This is not a complete token model, whole-feature acceptance or a new live acceptance result.

**R7 presentation approved after the performance checkpoint:** the owner selected
"Approve the recommended table wording and expandable selected-answer evidence". Keep the existing
table, approved sizing and scrolling; show plain-language authorization, own-account restriction and
readiness separately, with expandable stored identities, permission entries and direct/group route
for the selected answer. Keep capture-wide coverage limitations separate. This approves presentation
only, not discovery enablement, a numerical budget, authorization/storage changes or R8 acceptance.
Implementation and offline validation are recorded in the
Assets specification.
The approved presentation is implemented: 137 focused checks and the full 3,837-test suite passed,
and the solution builds. Selected evidence clears with failed or mismatched-generation reads.
This is offline validation, not real-product acceptance; laptop/monitor checks remain outstanding
normal verification and discovery is still inactive in both hosts. The subsequent R8 correction
reconciles these distinctions without accepting the whole feature.

**R8 reconciliation authorized after R7:** after the R7 checkpoint was committed and pushed, the
owner answered "ok do r8" to the bounded recommendation to check the stored-requester-to-screen
workflow offline and reconcile current-state claims across governing documents. This does not
approve discovery enablement, a processing budget, new UI wording/layout, further tuning or final
feature acceptance. Unperformed real-product and laptop/monitor checks remain outstanding; no new
commit or push is included in this instruction.

**R8 current-state reconciliation:** requester authorization, persistence, safe readback and the
approved presentation are implemented. Shared automatic discovery is implemented but inactive in
the shipped Shell and CLI until a numerical processing budget is approved. The new offline
workflow checks connect synthetic sealed evidence through real judging and file readers to both
object-screen directions, including stored proof, holder-count preservation, re-judging and read
failure clearing. They do not establish live-directory success, physical-display usability or
completed chains toward Tier 0. The R8 record
owns verification results and the remaining acceptance gates. R8's documentation correction is
complete for the delivered scope; final requester/Stage 6 acceptance is not.

**R2 owner requirement:** on 2026-09-06 the owner clarified that requester assessment "should always
run on new captures" and asked for a clearer explanation of the proposed interaction. An
existing-capture-only/manual-rejudge-first scope does not meet that requirement. Requester
assessment must run automatically during normal Shell and unattended CLI judging, including after
new Evidence is sealed. The judgement specification supplies the direction: start with a captured
permission's trustee, resolve relevant captured members and validate scope. Decision 0111's concrete
bounded requests do not require an administrator-maintained selection list. Discover questions from
each capture's own permissions and memberships, within the accepted direct-user and single explicit
global-security-group routes, including SELF resolved to the target. At that checkpoint, the remaining
approval boundary was how incomplete discovery, unsupported inputs and budget stops would be stored and
reported without implying negative authorization or complete coverage. This does not authorize a
forest-wide pair cross-product, live lookups, authorization/storage changes or the withdrawn
request-file proposal. Production integration was absent at that checkpoint; its later approval
and delivered-but-inactive implementation are recorded below.
When presented with a partial-coverage recommendation and a proposed 50-pair allowance, the owner
asked work to stop for a plain-language explanation because the proposed implementation was unclear.
That response is not approval of the allowance, partial-result policy or storage/readback changes.

**R2 processing-budget direction approved:** after the recommendation was revised to reject a
blanket 50-pair cutoff and establish a measured processing budget instead, the owner answered
"ok i apporove your proposal". The 50-pair recommendation is withdrawn. The existing library limit
of 100 submitted requests is not a measured forest-wide discovery limit and must not be repurposed
as one. Establish a numerical recommendation through bounded offline measurements before changing
production scheduling limits. No replacement number, silent batch truncation, authorization change
or specific storage/readback extension is approved by this budget-direction answer. Missing captured
evidence, unsupported analysis and processing-budget stops remain distinct. R2 was not implemented
at this budget-direction approval; the later schema-18 integration below supplies it without
approving a numerical production limit.

**R2 contract and integration approved, 2026-09-07:** after the recommendation was explained against
the actual Shell, CLI, evaluator and storage paths, the owner answered "i approve proceed".
This approves one shared permission-first automatic scheduler, both own-account Add and Remove
questions per concrete pair, schema-18 discovery coverage and limitation records beside the existing
answers, strict generation-bound readback, and minimum Shell/CLI coverage notices. The evaluator's
authorization rules, holder counts and explicit submitted-batch refusal remain unchanged. Missing
evidence, unsupported routes and processing stops remain separate. A failed or cancelled attempt
publishes nothing from that attempt. Older judgement results require re-judging, not re-capture or
rewriting historical generations. This approval does not establish a numerical automatic-processing
limit: measurements and approval of that recommendation still precede enabling a new production
limit. Implementation and validation are not implied by approval; P-145 and R2 remain open.

**R2 automatic discovery implemented in judgement schema 18, 2026-09-07, but not enabled in the
production hosts.** The shared judging path can discover own-account membership questions from each
capture's own permissions and memberships, inside the existing single pass over the bundle, when
given a discovery budget, and store answers beside a persisted record of what the scan covered.
Both the Shell and unattended command line currently pass no budget. Denies and uncertain entries
are discovered rather than filtered to the safe cases; broad trustees and NULL DACLs are recorded as
coverage limitations instead of being expanded into invented requesters; missing evidence,
unsupported routes and processing stops stay separate; a failed or cancelled attempt publishes
nothing and leaves the previous results as previous results. The authorization rules, the
own-account constraint and the counted holder edges are unchanged. **No numerical processing limit
has been approved, so the scan performs no work today and both hosts say so rather than staying
silent** — an empty requester product never reads as a forest where nobody can add themselves to a
group. Older judgement results must be re-judged to gain this; no Evidence, Derivation, retained
generation or frozen value was rewritten. Validated offline against synthetic sealed bundles with no
directory contact. The subsequent approved R7 presentation is implemented, and R8 reconciles the
current state. Real-forest verification, an approved budget and final acceptance remain outstanding;
P-145 and R2 production enablement remain open.

**Owner-approved priority after the full-volume performance comparison:** pause further discovery
tuning, preserve the validated permission-read fix, its regression tests and measurement artifacts,
and return to the remaining R2/R7/R8 integration, presentation and acceptance work in bounded
slices. Remeasure when work changes data access or processing volume, and before approving a
production budget, rather than after every presentation change. The completed synthetic measurements
and their limitations are recorded in the judgement store.
This is not approval of a numerical limit, enabling automatic discovery, new authorization behavior,
a new R7 presentation design or final feature acceptance. Laptop/monitor checks remain ordinary
verification work, not an additional session that must precede continued development.

**Session checkpoint requested by the owner:** update the governing documents, commit and push the
validated work, then resume in a new session. This explicitly authorizes that checkpoint commit and
push; it did not approve the then-proposed R7 requester-details presentation. The continuation session
obtained explicit approval before implementation; see the
R7 presentation record.
The owner subsequently requested a separate R7 commit and push, completed as `a92d592` on `main`.
The current R8 instruction includes no further commit or push. Keep further performance tuning
paused unless later work changes the measured workload or a remaining cost blocks the bounded feature.

**R6 presentation review:** the owner reviewed the synthetic gallery comparison and accepted the
proposed sizing, now implemented. The control table is capped
at 240 WPF layout units, the requester table retains its 180-unit cap, notices use their text's
height, and the section scrolls when the pane is short. The accepted trade-off is scrolling within
each table as well as through the section to reach notices, evidence and requester answers.
He plans to test the implemented product in his forest, on his small laptop screen and on a monitor.
The owner clarified that these checks will happen during normal verification, not as a separate
monitor-check session or a prerequisite to continuing R2, R7 and R8.
Those checks have not occurred here; preview approval is not real-product or forest acceptance.
No directory operation or retained-Evidence access is authorized by this presentation decision.

**Where judging time actually goes, measured 2026-09-22 — and it is not the storage format.** The
object pass had one clock on it, covering the rules, and the rules were 7.03 s of a 115.12 s interval
in the reproduction of the reported 108-second audit. The rest was measured by nothing, and three
saved-permission storage redesigns were aimed into it. The first breakdown, on the sealed laboratory
capture of 8,407 objects, put **15,544 ms of a 21,341 ms object pass into storing the saved
permission classifications, against 297 ms to reach the verdicts being stored** — writing cost about
fifty times more than deciding, and accounts for roughly 90% of the 17.3 s that P-248's saved
products added. Deriving the control edges, which is the analysis this product exists for, was
**19 ms**.

**Splitting that write twice over says the cost is SQL statements.** Shared entries 35.8%,
transaction commits 30.5% at 587 µs across 8,407 commits, entry rows 16.5%, schema support 10.2%;
and inside shared entries, 68.2% the insert and 19.4% a nested trustee-meaning proof write, with the
JSON comparison key only 6.1%. About **1.25 million statements** are issued per run, each on a newly
created command with its SQL re-prepared, plus a verification `SELECT` after every schema write,
twice per entry, against a table holding a few hundred rows.

**This is why the storage trials failed, and it was knowable at any point.** P-251 halved the result
file, 352,264,192 to 187,617,280 bytes, with no repeatable judging gain; P-249's first candidate
allocated 8.65% less and ran slower. **Fewer bytes is not fewer statements**, and no format redesign
changes the command, transaction, nested-write or verification counts. The format-44 candidate would
have done the same thing, and its three remaining judging runs were not spent finding that out.
Artifacts are under `next/artifacts/judging-object-breakdown/`; the instrumentation is permanent and
travels to the laboratory and to production, which has still never been measured.

**What was done about it, the same day.** Four changes, none of which alters a decision, a rule or an
answer: statements compiled once and rebound instead of a command created and parsed per row; schema
support verified once per distinct payload per run rather than twice per entry; the three per-object
writes sharing **one** transaction batched across 500 objects, which is stronger atomicity than the
three separate commits it replaced as well as cheaper; and **format 42**, storing each distinct
reading once under a SHA-256 fingerprint. On the laboratory capture the object pass fell
**21,211 → 12,766 ms (−39.8%)**, the permission write **15,410 → 7,157 ms (−53.6%)** and the
judgement file **352,264,192 → 180,301,824 bytes (−48.8%)**, with identical output throughout.

**Two limits on that, stated because they are easy to forget.** Every figure above is the sealed
laboratory capture judged on the development laptop. The 2026-09-22 laboratory run on standard SSD
put **18,463 ms** of a 49,919 ms object pass into commits against 1,979 ms for the same work on the
laptop, so the storage-dependent part of this is untested after the fixes — halving the bytes is
expected to help most exactly where it has not yet been measured. And the batch size of 500 is a
chosen number, not a tuned one; the laboratory showed its cost depends on the disk underneath it.

## The forest this is built for

**The owner's production forest is the scale that matters, and the laboratory is not it.** Recorded
because every performance and budget decision has to be argued against a real shape rather than a
convenient one, and because a session that measures a small synthetic capture and reasons from it
will reach a confident wrong answer.

| | |
|---|---|
| Domains | 9 |
| Objects | ~347,000 |
| Access control entries | ~5.9 million |
| Group Policy objects | ~3,500-4,000 |
| Control edges the predecessor produced | ~9 million |
| Delegations | ~1.3 million |
| Findings | ~34,000 |
| Directory depth | deep, average distinguished name about 97 characters |
| Predecessor's stored output after a production run | ~17 GB |

**The Group Policy count is the owner's estimate of 2026-09-22, not a measurement.** It was recorded because it changes the arithmetic of the SYSVOL pass by an order of magnitude and nothing else in this document carried it; the exact figure comes out of any capture, one row per declared policy in `gpo_coverage`, and should replace the estimate once a run seals.

**Every figure in this table came from the predecessor, and the rebuild captures more than it did.** Recorded 2026-09-22 after the owner corrected a comparison built on it: the object, ACE and control-edge counts describe what the OLD application gathered, so they are a FLOOR for this product and not its scale. Treating them as equivalent makes the rebuilt store look bloated when it may simply hold more. Until a sealed run reports its own counts, no size, budget or storage conclusion may rest on comparing a SecureAD.Next figure with the ~17 GB predecessor output or with any row above.

**Measured, 2026-09-23, from the first sealed nine-domain production capture.** These supersede the predecessor figures above for every purpose: the rebuild captures 2.7 times the objects and 24 times the access control entries the old application did, so any argument resting on the older numbers is wrong by that much. Taken with `securead-cli --describe`.

| | |
|---|---|
| Objects captured | 939,700 |
| Access control entries | 141,706,338 |
| Distinct access control entries among them | 481,967 |
| Times each distinct entry is stored | 294 |
| Distinct security descriptors | 271,845 |
| Entries per descriptor, average | 521 |
| Trustees | 189,192 |
| Group Policy objects | 3,453 |
| Objects whose permissions could not be read | 280,782 (30%) |
| Sealed evidence file | 51.08 GB |

**The 294 is the shape of a defect, and it was fixed on 2026-09-23 under `P-272`.** Each distinct
entry is now stored once and pointed at, so the row above describes how many times an entry is
*referenced* rather than how many times it is written. It is kept because it is the measurement the
redesign rests on, and because a figure taken from a bundle sealed before that date still means what
it says.

**What the fix is worth, measured rather than projected.** A synthetic bundle at this shape was
written by the real capture writer twice, at 5% scale, once on each side of the change. Both hold
identical evidence - 46,985 objects, 13,592 descriptors, 7,081,432 entry positions, 24,098 distinct
entries - and the only difference is how many rows were needed to say it.

| | Before | After |
|---|---|---|
| Rows stored to hold the entries | 7,081,432 | 24,098 |
| Entry tables, content | 676.4 MB | 78.5 MB |
| All tables, content | 946.2 MB | 348.3 MB |
| Sealed evidence file | 1,853,292,544 bytes | 620,806,144 bytes |
| Time to write it | 180.4 s | 89.7 s |

**Two-thirds of the file went, and it is 66.5% on a measurement rather than an estimate.** The part
that is arithmetic rather than measurement is what this means at full production scale: by content
per row the entry tables go from 23.10 GB to roughly 1.6 GB, which leaves `raw_bytes` - the sealed
original descriptor bytes, 7.73 GB - as the largest single thing in the file and the subject of
`P-269`. **The synthetic model's own before figure is 37 GB at full scale against the real capture's
51.08 GB**, because its trustees and descriptors are smaller than a real forest's; the ratio is what
the two runs measure, not the absolute size of a customer bundle.


**Where these come from, exactly.** They were first found in the predecessor's
`tests/SecureAD.Infrastructure.Tests/Performance/ObjectDetailProfiler.cs`, which states them as the
production environment it profiles against. **The owner confirmed them as still correct on
2026-09-07.** They are the shape to design and measure against.

**The 17 GB is the owner's own figure for the predecessor's production output, supplied 2026-09-22,**
and it is the only production *size* measurement this project has. Treat it as the order of magnitude
to plan against, not as a budget the rebuild must beat: the predecessor stored a deduplicated,
canonically ordered, generic-expanded ACL projection and **no raw descriptor bytes at all**, while
this product keeps the sealed original bytes and every distinction that projection dropped. The two
are not measuring the same thing, and the rebuild also splits its output into a sealed evidence file
and a separate judgement file. No production size has been measured for this product, and the
approved P-249 comparison runs are laboratory runs, so they will not establish one.

**The laboratory is `ad.lab`, about 8,383 objects, and the owner's words for it are that it "falls
far short" of production in both scale and complexity.** It is genuinely useful for testing
behaviour — that a rule fires, that an answer is right, that a screen refuses to mislead — and it is
not evidence about cost, volume or what a real directory contains. The 111,627 control edges
[`0097`](decisions/0097-a-group-held-permission-is-counted-at-the-group.md) argues against were a
*lab* number; production produced roughly eighty times more. A budget, threshold or timing measured
only on the lab or on a small synthetic capture is not a claim about a customer forest, and stating
it as one is the failure [`0002`](decisions/0002-absent-view-means-degraded-run.md) exists to
prevent.

## The five commitments

1. **Evidence is permanent.** Sealed once, never re-sealed. Re-analysis copies the source and seals
   the copy; the original is opened read-only (`0021`).
2. **A gap is a fact about the capture, never about the forest** (`0002`). A domain left out by
   choice never looks like one that could not be reached (`0063`); an unfinished run reports nothing
   at all rather than partially (`0068`).
3. **Say what you know, with its uncertainty — except when claiming completeness** (`0086`). Silence
   is reserved for *this is complete*, where a wrong answer makes someone stop looking.
4. **Severity belongs to the rule and the customer cannot move it** (`0066`, `0082`) — lowering a
   severity is quieter than accepting a finding and leaves nothing behind.
5. **A finding carries typed evidence and a permanent identity** (`0080`, `0023`, `0024`), so an
   acceptance made today still attaches after a rename.

## What it deliberately is not

- **Not intended to replace BloodHound, clarified by the owner on 2026-10-03.** The owner wants the
  richest practical evidence-backed rule and path coverage while keeping both judging and navigation
  usable, and requested an engineering assessment of which remaining path capabilities are too
  difficult or costly for that goal.
  This direction does not approve every possible path family, a processing limit or a new measurement
  campaign; the next implementation scope must distinguish established permissions, supported
  operations and capabilities that the captured evidence cannot prove.
- **Not a live tool.** No live effective access, inheritance, ACL compare or delegation reporting
  (`0008`).
- **Not a policy compliance checker.** Password policy is captured and shown; nothing grades it.
  Plenty of software measures password strength.
- **Not tunable.** No assessment modes (`0031`), no customer-editable catalogue (`0082`).
- **Not an auditor of audit configuration.** The SACL is never requested (`0036`).
- **Not a reporter of account activity, decided 2026-09-01.** Whether an account is really in use
  cannot be answered from one controller: `lastLogon` is per-controller and never replicated, and the
  replicated `lastLogonTimestamp` is documented by Microsoft as updating only once it is already 9 to
  14 days old, and as capable of holding a future value after a clock skew or a Kerberos S4U2Self
  request. Reporting a stale-account threshold from that would print an estimate as a finding, and it
  would under-report as readily as over-report. Sign-in telemetry — Defender for Identity — answers
  this properly and a directory attribute does not. `P-113` keeps two possibilities open: the
  timestamp shown as *information* on an asset rather than as an indicator of activity, and a
  separately named *rough estimate* rule, for customers without that telemetry, whose own wording
  would have to say it is an estimate.

## What tests are for, decided 2026-09-12

**Tests keep the code honest, never a document.** The owner's words: *"i dont want any test that point to
documenation. its done thing but slow developemnt way down. test to me should keep the code and how its
supposed to work honest."*

- **A test may check code against code, or code against an outside authority.** Microsoft's published
  specifications, a recorded output of the predecessor, a frozen lab result. Only those can say the
  product is wrong.
- **A test that checks whether a document and the code agree is deleted.** So is one comparing two
  documents. It confirms an opinion back to itself and doubles the cost of every change. `F-S44-2` is
  the price: three sound suites agreeing in both directions while fifteen captured attributes were
  silently missing, because the whole circle was anchored to the rules already written.
- **A drifting document is a documentation problem**, fixed by reading it, not by a failing build.
- **One exception, granted explicitly: the stage table** at the top of this file, held to the code by
  `StageStatusGateTests` and `next/tools/check-stage-status.ps1`. That table claimed *two* judging rules
  for long enough that twelve more were built underneath it. A stale stage table misleads the owner
  about his own product, which is a cost no other document here carries.

This removed 24 test classes on 2026-09-12, on top of the 260 deleted on 2026-09-11. **What it does not
buy is any claim that nothing in the product is dead.** The check that would prove that — every public
type reachable from a running entry point, gate 5b — was never built; see `docs/next/README.md` § Gates
and `F-S7-42`. The surface register retired with the other paperwork gates was never that proof, and its
own page said so.

## Where it departs from the predecessor

There is an old application. It worked, the owner ran it, and it is why this rebuild knows what it
is aiming at. **Its architecture is not this one's, and nothing below is a design to follow.** Its
inventory and component map were archived and are deliberately absent from this repository, so that
nobody treats it as a specification.

**The code, however, is on disk at `C:\Users\ba.admin\source\repos\razamus\SecureAD`, and the owner
has said to read it** — *"treat this as a source not a answer, look at what it did but also consider
if there is a better way"*, 2026-08-26. It is the only place a working findings screen for a real
forest exists. Read it for **how something performed**; never for **what the product permits**,
which the decision records settle and which it frequently contradicts.

Thirty-nine of seventy-nine decision records reference it. The load-bearing differences:

| | Old app | Here |
|---|---|---|
| Live directory | kept a live connection alongside the bundle | removed entirely (`0008`) |
| Sealing | signed at the end over evidence *and* conclusions; re-analysis re-signed in place | evidence sealed alone at capture, never re-sealed (`0030`, `0085`) |
| Analysis | eleven dependent phases writing into the same file | one streaming pass into a separate store |
| Failure | phases fault-tolerant, degraded results still presented | unfinished run reports nothing (`0068`) |
| Severity | overridable by policy file | fixed by rule card (`0066`) |
| Capture scope | two class filters as radio buttons | every class except a shipped noise list (`0034`) |
| Schema partition | not read | read every run (`0014`) — what makes object-specific ACE evaluation possible |
| Vocabulary | *Accept* on screen, *Suppression* in code | one word, **finding**, everywhere (`0066`) |

### Why it took hours, and why that is not inherent

**The owner's measurement, 2026-09-03: capture took 30 to 45 minutes across nine domains, and the
run took three to five hours.** The difference was after capture; that observation alone does not
separate path calculation from the other analysis phases.

**Correction, 2026-10-02: that timing does not establish the cause, and the old code currently on disk
already searches backwards from its targets.** In frozen predecessor `f0726569`,
`EscalationPathService.BuildAllPathsAsync` builds a compact graph, computes one reverse-distance
index starting at all high-value targets, then reconstructs representative shortest paths.
The default depth is five and the retained-candidate ceiling is 250,000; both belong to the old
product, not to approved rebuild budgets.
The old per-source forward-search API still exists, but it is not the active batch implementation.
Its classifiers still use the stored transitive membership closure, while path links use direct
memberships.

The earlier account here relied on the predecessor's CONTROL-EDGES-AND-PATHS description and
incorrectly attributed its reported hours to a forward search from every principal.
Neither that attribution nor the claimed orders-of-magnitude advantage is established for the
frozen code; the rebuild also searches backwards for its supported membership paths, and no new
old/new runtime comparison was performed.
The old selected-path detail reads an already-retained path and requests its individual permission
evidence, rather than rebuilding whole-forest path inputs for every selected path.
Preserving the rebuild's stronger source and permission qualification does not require that
whole-forest readback cost; the separate saved-path browsing finding remains open.

**One correction to a claim made in this session and left here so it is not repeated.** SYSVOL was
suspected of being a runtime risk on the strength of lab capture rising from 7 to 11 seconds when it
began working. The owner's account is that the old application captured little of SYSVOL and he is
not sure it was ever used in production, so there is no prior measurement to lean on either way.
It is unmeasured at scale rather than known to be slow.

### What its findings grid did, and what of it is worth having

Read 2026-08-26 from `SecureAD.Infrastructure/Paging/`, `Findings/FindingsService.Queries.cs`,
`Storage/DerivedStoreSchema.Views.cs` and `SecureAD.UI/ViewModels/FindingsGridViewModel.cs`.

**Keyset paging, and it is better than the obvious alternative.** `KeysetQueryBuilder` pages by
where the last page ended rather than by `LIMIT`/`OFFSET`. Offset paging makes the database walk and
discard every row before the page, so page 500 of a large forest costs 500 pages of work; keyset
paging costs one. Three details are the actual engineering, and all three are easy to omit and hard
to debug afterwards:

- **Every sort ends in a unique tie-breaker** — `severity, rule_id, target_dn`. Without it, rows
  that sort equal can straddle a page boundary and be shown twice or not at all.
- **The continuation token records the sort and a hash of the filter**, and a token that does not
  match them restarts from the first page rather than silently skipping rows.
- **Identifiers are validated against a strict pattern** before they reach the SQL text.

Its page size was 50, in `GridViewModelBase`.

**Filter values are read from the data**, so a filter cannot be set to something no finding has.

**Its grid resolved names by joining** `dim_principal` and `dim_object`, because findings and objects
were in one file. **They are not here** — findings are in `judgement.db` and evidence in the sealed
`evidence.db` — so what the grid shows is stored on the finding when it is made. That costs nothing
at judging time, because the object is already in hand when a rule fires, and it avoids the
alternative: fifty lookups into the evidence to paint one page, on every page and every re-sort.

**Three things in it are not worth having, and two are positions this product has reversed.**
`context_json` is the schemaless blob the judgement schema's own comments record as having silently
downgraded a finding when a value would not parse. `suppressed`/`suppression_reason` are `0066` and
`0082` reversed. And `v_grid_findings` rewrites a finding's coverage to *complete* inside the view,
by matching a `coverage_reason` string — a judgement made in presentation, where nobody reading the
finding can see it, which is `0002` exactly.

**Reading it found a defect here.** The old app's severity sorts correctly because its view does not
order on the text. This judgement store writes `severity` as the enum name, so `ORDER BY severity`
gives Critical, High, Low, Medium — alphabetical, putting Low above Medium. A rank is stored beside
the name to fix it.

### What its finding detail view showed, and what of it is worth having

Read 2026-09-01 from three screenshots the owner supplied of the predecessor's finding window
(`SEC-014`, `SEC-024`). This is the screen an administrator actually works from, so what it did well
matters more than most of the old code.

**Its blocks, in order:** a header carrying rule identifier, title, category (`Delegation`,
`CredentialTheft`), a MITRE technique link and a severity badge; **What was found**; **Evidence
context**; **Why it matters**; **How to fix**; a strip reading `Coverage: Complete  Suppressed: No
Tags: …`; and the buttons *View evidence*, *Accept risk*, *Copy finding key*.

**Worth having, and settled 2026-09-01:** the category, the MITRE link, **Why it matters**, **How to
fix**, and the coverage signal. The owner's decision on where they belong: **in the product, not only
in an exported report** — *"I can see server admins using this as a working app on what to clean up,
and seeing it on screen in a UI is sometimes easier to consume than a report if done right."* So the
finding view is a working surface, not a preview of a document.

**The one thing to change is duplication, not volume.** Of the eleven rows in *Evidence context*,
seven repeat the panel directly above them — rule id, source SID, subject name, target DN, target
name, control type and classification are all already on screen. Of the remaining four, three
(`Source Is Well Known Admin`, `Source Is Privileged By Membership`, `Source Is Broad Principal`) are
the *working behind* the classification line rather than an answer, and the fourth is an internal
edge identifier. The `Detail` sentence then states the same facts a third time, using a raw SID where
the name is two lines above.

**This is not a matter of taste, and the screenshots prove it.** On the owner's laptop the duplicated
block pushed **Why it matters** and **How to fix** below the fold, so the two things he most needed
were the two he could not see. Removing what is printed twice is what brings them onto the first
screen.

**The agreed shape, 2026-09-01:** four blocks — header, *What was found*, *Why it matters*, *What to
do* — with everything raw (identifiers, GUIDs, ACE hashes, the classification working) behind *View
evidence*, which the predecessor already did well. The rule to apply when deciding where something
goes: **the finding page answers what, how bad, why and what do I do; the evidence view answers prove
it.**

**Not worth having:** `Suppressed`, which [`0066`](decisions/) and [`0082`](decisions/) reversed, and
the *Evidence context* table on the front page.

**What must not creep in.** *How to fix* states an action and what it may break. It must never state
that the action makes the customer safe — that is a claim about every path to the object, which
`AC-15` and `AC-21` require to be proven, and it is stage 8 work. Guidance copy is where that line
gets crossed by accident.

**Content is stage 4; presentation is stage 9.** The guidance is written as each rule is built, while
the Microsoft research behind it is in hand; the screen that displays it is designed later, around
content that already exists.

**Every rule gets an About section, and it is where a limitation is stated, decided 2026-09-02.** The
owner: *"we will have an about section that describes each rule and what its looks for so we will have
the ability to surface the limitations to the user in that capacity."* So a rule has three kinds of
copy, and they answer different questions:

| | Answers | Scope |
|---|---|---|
| A finding | what is true about **this object** | one object |
| Guidance (\`RuleGuidance\`) | why that matters and what to do about it | the rule |
| About | **what this rule looks for, and what it does not** | the rule |

**This is what makes a bounded rule honest.** A rule that reports a subset is not free to let its
silence read as *nothing else is wrong*; About is where the boundary is stated to the operator rather
than only to a reviewer reading the rule document. \`SEC-027\` is the first rule to need it: it reports
SID history containing a **well-known** privileged identifier and cannot rank a custom group from a
domain that no longer exists, and an operator must be able to read that without opening this
repository.

It is content, so it is written as each rule is built, alongside the guidance. Where it is displayed
is stage 9 with the rest of the presentation.

**Built 2026-09-03, and it is required on every rule.** `RuleGuidance.About` is not nullable and
`RuleGuidanceTests` refuses a blank one. Optional was the cheaper choice and was refused for a
reason worth keeping: a field populated for some rules and empty for others is rendered by a screen
as *this rule has no limitations*, which for a bounded rule is the exact false statement the section
exists to prevent. Being obliged to write it is also how an unstated limit gets found — writing the
eleven turned up three nobody had said out loud, including that `SEC-028` reports an account
**exempt** from the password length rule rather than one with no password.

**It is shown on the findings panel, which is half of what it is for.** The operator who most needs
a rule's boundary is the one reading a rule that reported *nothing*, and he never opens a finding.
The rest waits for a screen that lists the rules themselves.

## Build order, and two scope decisions

**The dashboard is built before the remaining rules, decided 2026-09-05.** The owner asked whether
it had to wait until every rule existed; it does not, and it should not. Stage 2 depends on nothing
unbuilt. Building it early puts the wording in front of an administrator, which is the only way to
find out whether it reads correctly to the person who has to act on it. The order the owner set:
**dashboard, then a punch-list session, then stage 6**.

**A correction: this paragraph claimed the product had *no screen that shows findings to anybody*,
and that was false.** Corrected 2026-09-05 against the code. `AssetsPane` has had four working
panes bound to live stores for some time — `Objects` and `Laps` over sealed evidence, `Findings` and
`Rules` over the judgement store — and the findings pane already distinguishes *every rule ran and
matched nothing* from *nobody has judged this bundle*. The claim survived into this document because
it was written from a roadmap row rather than from `AssetsViewModel`. What was genuinely missing was
the answer to *what am I looking at*, which is what stage 2 supplies.

**The dashboard was built 2026-09-05 and the owner settled four things about it.**

1. **Coverage first, counts underneath.** How much of the forest was read is stated before any
   number on the screen, and stated every time — including when nothing was missed, so that its
   absence is never read as reassurance.
2. **Counted per domain, totalled afterwards.** A single forest-wide figure cannot show a hole: a
   run that read two domains of three produces a smaller number, and a smaller number looks exactly
   like a smaller forest. An uncovered domain is a visibly present row carrying no figures.
3. **Where a shortfall can be counted exactly, both numbers are shown.** The owner's wording: *if we
   can show how many were read and how many were not then we show the exact numbers.* This applies
   to Group Policy, the one place a sealed bundle can state an exact shortfall — the policies are
   declared by the directory, which is read all-or-nothing, while their files come from SYSVOL,
   which `0044` allows to fail without failing the run.
4. **The dashboard is the landing screen for an opened run.** A failed, interrupted or damaged run
   never reaches it: the owner's observation, confirmed in the code, is that such a run *never
   finished capture*, so there is no sealed evidence to land in. The library states what became of
   it instead.

**A domain cannot be reported as partly read, and the owner was right to question it.** Asked what
the screen should say for a partly read domain, he asked when that could happen — *wouldn't the run
be discarded?* It would. Capture is fail-fast per `0003`: a domain that cannot be read ends the run
before the seal, `UnreadOutcomeIsUnreachableTests` holds that no production code records a unit as
unread, and `BundleReader.ReadScope` refuses outright to open a bundle claiming otherwise. The
reachable gaps in an openable bundle are a domain excluded by choice, a domain the forest named no
writable controller for, and a SYSVOL read that partly failed.

**A count is never rendered for a domain that was not read, and the type enforces it.**
`DomainInventory` holds its counts behind `TryGetCounts`, which answers false for every outcome but
`Read`, and its factories refuse both contradictions at construction. There is no zero available to
render for an unread domain even if the screen's markup were wrong. See
layers/shell/what-a-run-counted.md.

**Tier 1 means what Microsoft says it means, decided 2026-09-05.** Per the
[tier model](https://learn.microsoft.com/windows-server/identity/ad-ds/tier-model), Tier 1 is
*enterprise servers and applications*: member servers and server administrator roles, the solutions
that manage them (backup, monitoring, patching, hypervisors), Microsoft server applications such as
Exchange, SharePoint and SQL Server, third-party server solutions, and line-of-business
applications. Tier 2 is end-user devices and accounts.

**Tracing to Tier 1 servers is deferred to the very end and may never be built, decided
2026-09-12.** The owner: *"i care about teir 0 and teir 0 adjecent."* Tier 0 is derivable from the
directory - Microsoft names the groups. **Tier 1 is not.** Nothing in Active Directory marks a
member server as an Exchange server or a line-of-business host; the tier model is an operational
structure an organisation adopts, expressed in OUs and groups it chose the names of.
`operatingSystem` distinguishes a server from a workstation and says nothing about what it carries.
So a Tier 1 rule must either read a customer-supplied definition or infer one, and **inferring it
would be this product asserting a tier boundary the customer never drew**. Recorded as `F-S45-12`;
nothing is waiting on it.

**This does not defer `SEC-073` and `SEC-074`, which the owner does want.** Despite their names,
neither rule targets a member server. Both name a fixed set of built-in groups - Account Operators,
Server Operators, Print Operators, Backup Operators, Cert Publishers, RAS and IAS Servers, Remote
Desktop Users, Incoming Forest Trust Builders - and every one is already known to the product
through `ProtectedGroupCatalogue` and `WellKnownSidCatalog`, with membership resolved by
`ProtectedPrincipalClosure`. They need no customer-supplied anything. What they need is multi-hop
path chaining, which is Stage 6 control-edge work. Recorded as `F-S45-11`.

**Group Policy is deferred to the end, decided 2026-09-05.** The owner: *"i may leave until the end
unless it will be harder then but i dont see why it would be."* **It will not be harder later**, and
the reason is worth recording: the five GPO rules are blocked on a capability the product does not
have - reading policy *content* out of files on SYSVOL, rather than reading the policy object in the
directory. That capability is self-contained, it is the same amount of work whenever it is done, and
nothing else in the roadmap depends on it. Deferring it costs nothing but the findings themselves.

**Stop throws the work away, at every stage, decided 2026-09-12.** The owner: *"at any stage of the
audit, if the user hit stop, it should get thrown away. im not going to try and figure out how to
handle incomplete data from a user hitting stop."* **This is already how capture, derivation and
judging behave** - each writes `<name>.db.partial` and renames it as its last act, so a run that was
stopped has no file under the name a reader opens. Ordinary re-judging leaves the previous
judgement intact on cancellation, which is the same guarantee a crash gets by the same mechanism;
the explicitly confirmed discard-first action approved on 2026-10-02 is the deliberate exception,
because its previous judgement has already been removed before the new attempt starts.

**The rule also governs analysis started from Home.** The shell offers initial deriving and judging,
and the confirmed discard-first rejudging action described above reuses captured evidence and derived
facts without copying the bundle.
Stopping still requires deleting the interrupted attempt's output rather than keeping it for the
operator to interpret; the remaining unfinished-file cleanup gap is recorded in `PUNCH-LIST.md`.
**No screen may offer partial results from a stop**, and nothing may ask an operator to decide what
an incomplete judgement means; unfinished diagnostic files on disk are not completed results.

## What a control edge means, decided 2026-09-05

Stage 6 turns permissions into *this principal can take over that object*. Four things about what an
edge **means** were settled before any of it was built, because building it first would have chosen
all four by accident.

**The following edge and screen descriptions are accepted requirements, not built features.**
Control edges, their executable control-plane catalogue and these two views remain stage 6 work.

**A correction first: the product already judges ownership, and `P-70` said it did not.** `SEC-031`
reports an ordinary object owned by a principal that is not administrative at `Low`, `SEC-032`
reports the same for objects `AdminSDHolder` protects at `Medium`, both are registered in
`RuleCatalogue.All`, and `ObjectOwnershipEvidence` carries the owner, the object class, a
completeness voucher and whether the owner still exists at all. `SEC-060` already treats `WriteOwner`
as takeover-class only where an owner's implicit rights survive, consulting the `OWNER RIGHTS` entry
and the forest's `BlockOwnerImplicitRights` setting and refusing to answer where that setting was
never read. The row was prose, and prose is discussion. Verified by opening `ObjectOwnershipRules.cs`,
`ObjectOwnershipEvidence.cs`, `BroadPrincipalCanTakeOverObject.cs` and `RuleCatalogue.cs`.

1. **Ownership is an edge, but only where the owner is not an administrator** - the same set
   `SEC-031` and `SEC-032` already report, decided using the existing `ObjectOwnershipReading` rather
   than a second definition of *administrative*. An owner implicitly holds Modify Permissions, so
   without this the graph misses the most direct takeover there is; with it, an object owned by
   Domain Admins would produce no ownership edge. Actual edge counts await stage 6 and P-145.
   [`0095`](decisions/0095-ownership-is-a-control-edge-where-the-owner-is-not-an-administrator.md).
2. **Effective permissions are shown two ways over one stored edge set** - object-first (*who can
   take over this object*, the shape of the Windows Effective Access tab) and principal-first (*what
   can this service account reach*). One store, two queries, so the second view is cheap and the two
   can never disagree. A second correction: `EffectiveAccessCalculator` already computes this,
   denies before allows and inheritance included, and `P-71` said nothing did.
   [`0096`](decisions/0096-effective-permissions-are-shown-object-first-and-principal-first.md).
3. **A permission held through a group is counted at the group and expands to its members.** The
   headline reads *Helpdesk (400 members) can take over OU=Finance*; one click lists the 400. The
   counted edge names what an administrator actually changes - the access control entry - while the
   membership size stays visible instead of being multiplied into the total.
   [`0097`](decisions/0097-a-group-held-permission-is-counted-at-the-group.md).
4. **Every edge is tagged expected or unexpected, and the screen defaults to unexpected while saying
   how many it hides.** *42 unexpected control edges (111,585 expected, hidden)*. Nothing is
   discarded and nothing is silently suppressed. A broad principal - `Everyone`, `Authenticated
   Users`, `Domain Users` - is never expected, whatever it holds.
   [`0098`](decisions/0098-a-control-edge-is-expected-or-unexpected.md).

**The fourth is the one the predecessor got wrong, and its number is the evidence.** It reported
**111,627 control edges and 0 escalation paths** on an eight-thousand-object lab. A number that large
is not an answer; it is a number an operator learns to scroll past, and the real one hides inside it.
Stage 6's target is a small *unexpected* count, not a large total.

**The earlier prerequisites are resolved.** `P-85` is settled by
[`0099`](decisions/0099-the-tier-0-control-plane-catalogue.md), and `P-105` was fixed by `0106`:
the stored protection reason uses a nearest root rather than whichever root was processed last.
That single stored reason is not the complete membership explanation now required by `0108`;
P-146 now supplies the separate grouped route evidence and presentation. `P-107` and `P-67` do not
gate stage 6 and remain deferred for the reasons on their rows.

## Control-edge categories, decided 2026-09-06

**Membership changes and replication have their own categories**, accepted by the owner under
[`0110`](decisions/0110-membership-and-replication-have-distinct-control-edge-categories.md).
Add `MembershipEscalation` and `ReplicationControl` without renaming existing categories.
`DirectoryControl` describes authority over the object's security descriptor;
`CredentialExposure` describes credential-related capabilities. The existing specification's
`ConditionalEscalation` vocabulary is retained, not silently removed.

**The distinction is what a capability does, not how bad it is.** Resetting a password,
changing group membership and replicating secrets must not all be described as rewriting an
object's permission list. Self-Membership remains distinct from unrestricted membership changes.
A replication capability keeps its qualifying rights and the partition it reaches.

Microsoft's control-access-right, Self-Membership, Reset Password and replication-right pages
were read in full before the recommendation. They support the different operations; these category
names are SecureAD vocabulary, not Microsoft's taxonomy. Severity, expectedness, group counting,
owner acceptance and the claim-specific laboratory gates are unchanged. In particular, the new
replication category does not make a domain controller's edges expected or hidden.

**This records the accepted category choice, not an implementation.** Stage 6 and P-145 remain
outstanding; the rest of the stage-6 proposal is not accepted merely by this decision.

## Which principals are the control plane, decided 2026-09-06

**The control plane is the set of principals whose control the product may hide as routine, and
nothing wider.** Two questions look like one and are not: *can compromise of this principal reach
Tier 0* is Microsoft's tier model, and *should what it holds be hidden by default* is `0098`. A
principal can be Tier 0-sensitive without every permission it holds being expected.
[`0099`](decisions/0099-the-tier-0-control-plane-catalogue.md) settles `P-85` on that distinction.

**The accepted catalogue requires every entry to declare two scopes**, and an entry that does not declare an unrestricted capability
scope does not get one. **Authority scope** is where the principal is an administrator; **capability
scope** is which powers are normal for it. Unrestricted, within their own domain: the built-in
Administrator (500), Domain Admins (512), `BUILTIN\Administrators` (544); forest-wide: Enterprise
Admins (519). Restricted: **Schema Admins (518)** for the schema partition only, **SYSTEM** only
where a descriptor names it directly, **Enterprise Domain Controllers** only for the capabilities a
controller needs.

**Everything else is out, and out does not mean safe.** Backup Operators (551) and Server Operators
(549) stay Tier 0-sensitive and remain worth watching; excluding them means their edges stay visible
rather than being hidden as routine. Also out: Account Operators (548), Print Operators (550),
Replicator (552), Group Policy Creator Owners (520), Key Admins (526), Enterprise Key Admins (527),
the RODC groups (521, 498) and Domain Controllers (516). **CREATOR OWNER is never a holder at all** -
it is a placeholder for who a holder will be later, so its edges are `Unknown` rather than expected
or unexpected, which is what the product already does everywhere else.

**A correction to the record: the `CN=Keys` claim is true.** Microsoft's domain-wide schema updates,
operation 83, grants Key Admins and Enterprise Key Admins Full Control over the `CN=Keys` container,
inheriting, including rewriting permissions and taking ownership. An earlier draft of section 12
said it was not found; that section has now been corrected. The source is the same page `P-86`
already cited. It does not change the answer - `CN=Keys` holds key credential objects rather than
accounts, and Microsoft's own operation 89 later cut the grant back to a single attribute - but the
row was right and the specification was wrong, and it was caught by fetching the page.

**The earlier ownership implementation conflicted with the control-plane policy.** Its identifier
list and protection fallback accepted five operator groups as owners. P-140 was corrected by
`0107`: owner acceptance is independently derived, and the five groups no longer qualify by that
route. `0109` subsequently added schema-only acceptance. None of this means the stage 6 executable
catalogue already exists, or that ownership and control-edge expectedness are one interchangeable
question; `0101` requires the questions to remain separate.

**The accepted policy is automatic certificate-authority discovery and declaration-only AD FS.** An enterprise CA is an object
the directory names, in a partition capture already reads, so classifying it is a read. Nothing marks
an AD FS server, so naming one would be a guess - and a guess printed as a fact is the one thing this
product must not do.

P-142's bounded enterprise CA classification is implemented and offline verified; the declaration
mechanism remains implementation work on P-143.

**Customers may declare Tier 0 assets, never Tier 0 principals.** Declaring an asset adds something
to watch and hides nothing. Declaring a principal would hide edges by default and make conclusions
depend on local configuration. A specific edge that is fine here is handled by accepting the finding,
which stays on the record. **A declaration never moves a severity** - that is fixed by the rule
(`0066`, `0082`).

**P-143 is deferred until after the main feature/rule work; its entry workflow remains undecided, 2026-10-03.**
The owner explicitly lowered this feature's priority rather than making it a Stage 7 completion
prerequisite; the wider supported paths and remaining distance/tier summaries are not deferred with it.
The owner is considering the workflow while testing the latest SEC-071 correction in the laboratory;
neither a captured-object-only picker nor manual pre-run entry has implementation approval.
The owner notes that selecting objects from an earlier audit preserves recorded names, whereas
manual entry before a run introduces misspellings and other typing errors.
A small live name-validation step before adding an asset was raised as a possible alternative, not
authorized live access or an approved design.
Keep this decision pending: any proposed connected validation must respect capture's exclusive
directory-access boundary, and saved-result browsing must remain passive.

## What was settled alongside the control plane, 2026-09-06

**SYSTEM is expected where the object's own permissions say so, and nowhere else**
([`0100`](decisions/0100-system-is-a-descriptor-native-expected-trustee.md)). `S-1-5-18` sits with
full control in the default permissions of nearly every object in Active Directory, so treating it
as unexplained would have put tens of thousands of entries on the first screen - the same failure the
predecessor's 111,627 was. Treating it as an administrator everywhere would have been worse. The
answer is neither: **SYSTEM is expected for exactly what an applicable permission entry on that
object grants it, and that expectation transfers to nobody.** A service running as LocalSystem on an
ordinary server is not SYSTEM on the network - Microsoft says it authenticates as the computer - so
the product never lets SYSTEM quieten a computer account's edges. An unreadable descriptor still
produces *unknown*, never *expected*.

**Domain controller edges are grouped, never hidden**
([`0105`](decisions/0105-domain-controller-edges-are-grouped-never-suppressed.md)). Every controller
holding replication rights is normal, and a screen listing them one by one looks like hundreds of
defects. So they are grouped by holder and naming context, labelled as controllers where that is
established, and anything unusual the same account holds is shown apart from the routine block.
Nothing is suppressed. **No *this is just a DC* exception exists**, and it will not until the product
can tell an ordinary controller from a demoted one still holding rights it should have lost - which
is exactly the finding worth having.

**An expansion that ran out of room says so** ([`0102`](decisions/0102-group-expansion-is-budgeted.md)).
Group membership is expanded against explicit budgets - how many objects, how many links, how long,
how much stored. Reaching one never drops the finding and never discards what was found; it marks the
expansion **incomplete**, records which budget stopped it, says so on screen, and refuses to present
the partial number as a total. Microsoft publishes no safe threshold for this, so the product does
not invent one and call it safe.
The accepted timing clarification under `0102` is that deterministic replay covers traversal order
and work-limited prefixes for the same evidence, semantic versions and configured node/link/storage
budgets; elapsed-time cutoffs can stop at different fresh-run prefixes, while persisted partial
results reopen exactly as stored. This clarification does not approve or change production limits.

**Confidence flows one way** ([`0103`](decisions/0103-an-established-primitive-is-not-contaminated-by-an-unverified-compound.md)).
*This principal can take ownership* is proven from the permissions. *Taking ownership then lets it
rewrite everything* depends on a step nobody has verified against a real forest yet. The first is
reported as established and the second as unknown - the uncertain step does not drag the proven one
down with it, because that would make the product quieter about something it can actually prove.

**The replication capability is called `CanReplicateSecretDomainData`**
([`0104`](decisions/0104-the-capability-is-named-canreplicatesecretdomaindata.md)), matching
Microsoft's own words rather than claiming *all* secrets, which filtered attribute sets make untrue.

**One registry of principals, with each question answered separately**
([`0101`](decisions/0101-one-versioned-principal-registry.md)). *Is this group too broad*, *is it
suspicious in SID history*, *is it an acceptable owner*, *is its control routine*, *is it a Tier 0
asset* are five different questions about the same group, and one flat privileged-or-not list would
erase all five. Backup Operators is worth watching, is not an expected controller, and is no longer
an accepted owner - all at once, without contradiction. Nothing is inferred from anything else unless
a decision says so.

## Which membership a finding names, decided 2026-09-05

**One finding must summarize independent membership routes, including longer routes**, decided by
the owner under [`0108`](decisions/0108-a-finding-summarizes-independent-membership-routes.md).
This revises `0106`'s choice to name only the nearest privileged group. The derivation retains
that selected protection basis and now also stores the independent membership-route summary.
SEC-021 version 2 carries that summary in one finding. A principal protected in its own right retains that
direct catalogue basis rather than being relabelled as protected through membership.

**What was wrong.** The walk let each later group overwrite an earlier one, so the *last* one it
happened to process was reported. Three accounts sitting directly in **Enterprise Admins** on
`ad.lab` were each reported under **BUILTIN\Administrators**, because Enterprise Admins is nested
there. Nothing said was false - the accounts really are under both - but the answer shown was the
wrong one to act on. The fix is to remove the account from Enterprise Admins; removing it from
`BUILTIN\Administrators` would not have taken its privilege away, because it is not directly in that
group at all.

**Why not a separate row for every outer group reached.** Where several groups are reached through
the same membership, those outer groups are consequences of that route, not separate removals.
Counting each one would multiply rows by nesting depth rather than by the memberships an operator
can change. That reasoning does not apply to an independent route, even when it is longer.

**A correction from source inspection, 2026-09-05.** This page previously claimed the whole chain
to every outer root was stored and shown on a detail view. At that point `ProtectedPrincipalClosure`
held one basis and one path per principal, stored in `protected_principal_path`. The alternative
route evidence was genuinely missing. P-146 has now added it separately; the result is supporting
chains grouped by initial membership, not an exhaustive list of every possible path.

**The owner selected option 3 for P-146 on 2026-09-05.** Two direct memberships in privileged groups require two
removals, and naming one hides the other. Equally near nested roots can instead share an initial
membership; an independent route can also be longer. The tie-break makes a choice stable, not
complete. These were the three choices; option 3 is accepted and the other two were not selected:

| Option | Example finding text | Cost and limitation |
|---|---|---|
| 1. Name every equally nearest root in one finding | Alice reaches Domain Admins and Enterprise Admins through two direct memberships. | Store multiple roots and paths and update finding evidence and presentation. Avoids duplicate rows, but longer independent routes remain unmentioned. |
| 2. Name one and count the other equally near roots | Alice reaches Domain Admins; one other equally near membership also exists. | Still derive the alternatives and provide their details. Shorter headline, but an extra click is needed to learn the other membership. |
| 3. Summarize independent membership routes in one finding | Alice has two membership routes to privileged groups. Review both. | Most derivation, evidence and presentation work. Include longer independent routes, show the memberships that start them, and group routes sharing an initial membership rather than adding a row per outer group. |

**Why option 3.** Fixing only ties leaves the same failure when another
independent route is longer. An initial membership means the group the account directly belongs to;
it is not every outer group reached through that group. The finding must not claim that removing listed
memberships removes every other form of privilege. That stronger claim requires the later work that
proves a proposed repair covers every route.

**Implemented under 0108.** Derivation schema 10 stores independent initial memberships, the
reachable catalogue roots and supporting chains, including longer routes to the same root. The
chains retain captured names, scoped SIDs, primary-group links and separate authorization/protection
answers. Initial memberships sharing several outer roots produce one detail block, not extra
findings. SEC-021 version 2 persists the evidence in judgement schema 14; both finding screens expose
it through **View membership evidence**. Direct catalogue protection is retained in its own right,
and owner acceptance is neither reconstructed from this summary nor changed by it.

**Incomplete is visible, not discarded.** Limits on principal visits, examined links, estimated
stored evidence and time stop the walk with a named reason. Capture gaps and cycle-limited group
answers are also explicit. Known routes survive, their count is not called a total, and a proven
finding survives with unresolved inputs recorded beside it. This required correcting `JudgingRun`,
which previously discarded findings from an incomplete verdict. A rule that throws still loses its
findings. Distribution nesting can confer protection without authorization; the wording now says
so rather than promising that every protected account has domain administration.

**Checks were observed failing, one mutation at a time.** Retaining only one route failed 17 checks
across derivation, storage, judging and presentation. Erasing completeness failed six; mislabelling
distribution paths failed three; capture-dependent ordering failed one. Disconnecting each real
screen's binding failed separately, naming `SelectedFinding.MembershipDetails` and
`MembershipCompleteness`. Removing SID scope and primary-link labels each failed their dedicated
check. Every mutation was restored. The full-suite architecture checks also required completeness
on each initial-membership block, rather than only on its containing summary.

**P-149's remaining checks are implemented.** Before changing the stored layout, the existing
version-1/version-8 refusal and matching-version tests were verified against their bodies. Disabling
refusal made both mismatch cases fail; an added unversioned production column failed the independent
schema-9 layout checkpoint. Schema 10 has its own checkpoint, and the schema-9 checkpoint is retained.
The guard covers structural changes, not semantic-only changes with identical SQL; those still need
an explicit version decision and behavioral tests. Version-9 refusal is now tested too.

**The same sealed ad.lab evidence was checked again on a new copy.** Existing diagnostics, run with
`pwsh`, derived and judged next/artifacts/membership-routes-0108/ on the measuring machine. SEC-031 remains **10**, SEC-032
remains **0**, and both retain **four undecided objects**. All ten ownership finding details match
the preserved scoped result. Evidence retains SHA-256
2DEF9F8AD4DE01877970B7F97F845716C1FFC1B093B01F388004610526E76BE4. Derivation generation
69c75821-3f63-4045-806d-d9c7513c1fc4 records three initial memberships for `ba.admin`, with outer
Administrators roots grouped under their actual initial membership. Judgement generation is
1685f45e-0ea0-49cc-89b9-34df2b37c5af. Reports are `next/artifacts/p146-lab-*.txt` and
`p146-prior-ownership.txt`. This bundle has no SEC-021 findings; planted end-to-end tests prove the
multi-route finding and partial-finding cases. No control edge or stage 6 implementation was added.

## Who counts as an acceptable owner, decided 2026-09-05

**Owning an object and being repaired by AdminSDHolder are two different questions, and the product
now answers them separately**
([`0107`](decisions/0107-an-accepted-owner-is-a-separate-question-from-protection.md)). An object's
owner can rewrite its permissions without appearing in the permission list, so who owns something is
a control question. The five operator groups `0099` leaves out of the control plane - Account
Operators, Server Operators, Print Operators, Backup Operators and Replicator - are **no longer
accepted owners**, so an object one of them owns is now reported. Out still does not mean safe:
Backup Operators remains Tier 0-sensitive, and this makes its ownership visible rather than hidden.

**CREATOR OWNER and SYSTEM stay accepted**, because an owner recorded as a placeholder or as the
platform is a directory artefact rather than a person. `0099` governs the first and `0100` the
second.

**Two things were found by opening the code, and both changed the work.** First, the shipping list
was not what decided this: where the list did not match, the rule asked whether AdminSDHolder
protects the owner and read that as *administrative*. All five operator groups **are** protected, so
removing them from the list alone would have changed nothing a customer could see, while every test
of the list went green. Second, the answer could not be filtered out of protection afterwards either,
because the derivation records only one group as the reason - an account in both Domain Admins and
Account Operators would have been reported as a non-administrative owner, which is the product
stating something false. So *is this an acceptable owner* is now derived once in its own right,
walked over the accepted groups alone, and stored beside the protection answer rather than inside
it. That is the first of the five questions [`0101`](decisions/0101-one-versioned-principal-registry.md)
requires; the other four are scheduled, not folded in.

### Schema Admins ownership has a target scope, decided 2026-09-05

**Accept the forest-root Schema Admins group and its members as owners only within that forest's
schema partition**, including the schema root itself. The owner selected both the group and its
members, recorded in [0109](decisions/0109-schema-admins-ownership-is-accepted-only-in-the-schema.md).
Ownership elsewhere remains reportable unless a separate accepted membership gives broader authority.
Someone in both Schema Admins and Domain Admins must not lose the broader acceptance.

The group is identified by its forest-root SID, not its name or RID 518 under any domain. The target
must be in the captured forest's schema, not merely under a similarly named container. Protection
by AdminSDHolder does not establish this answer: ownership acceptance remains independently derived.
Distribution nesting is not administrative authority. When a schema membership is proven but other
membership evidence is incomplete, acceptance inside the schema is known and acceptance elsewhere
may remain unknown. Missing forest identity must not authorize the exception.

**Implemented and verified against the same evidence.** `OwnerAcceptance.SchemaOnly` and
`OwnerAcceptance.SchemaOnlyOtherwiseUnknown` preserve the scoped answer and uncertainty outside it.
The unrestricted list still excludes RID 518. Derivation schema 9 refuses older owner semantics;
both ownership rules are version 2. `JudgingContext.ForestFqdn` supplies the captured forest identity
to the target check, and explain mode now supplies the same inputs as normal judging.

On a copy of ad.lab-20260905-212426, re-deriving and judging changed SEC-031 from **1,788 to 10** and
left SEC-032 at **0**. Both still reached 8,379 verdicts with **four undecided objects**. The removed
findings are exactly the 1,778 Schema Admins/schema cases; the ten machine-owned findings remain.
The schema root was also checked through explain mode, which reports a reached verdict and no
ownership finding. Evidence retained SHA-256
2DEF9F8AD4DE01877970B7F97F845716C1FFC1B093B01F388004610526E76BE4. The scoped derivation generation is
f67940b1-105c-4092-916e-d8b2bcb5c730. Artifacts remain in
next/artifacts/ownership-volume-20260905/, with the scoped prefix and scoped bundle copy.

**The checks were observed failing.** Removing the scoped membership roots caused four derivation
test failures, including *expected SchemaOnly, actual NotAccepted*. Inverting the target boundary
caused all ten scope cases to fail: legitimate schema ownership was reported and outside ownership
was accepted. Restoring both changes gave 120 passing targeted derivation, persistence and ownership
tests. The schema-8 refusal test failed before the version bump and passed afterwards; the actual
schema-8 lab store was also refused with both versions named before it was re-derived. These checks
did not detect every future schema edit made without a version bump. P-149's independent structural
checkpoint and disabled-refusal control have since been implemented with P-146, described above.

**P-147's measured blocker is resolved.** That correction built no control edges or multi-route
presentation; P-146 subsequently implemented 0108's route explanation. Stage 6 has since produced
control-edge output, and its measured P-150 correction is linked above. P-145's expectedness and
visibility acceptance subsequently closed on 2026-09-12, without closing separate capability-specific
laboratory or customer-scale gates. The ten remaining ownership
findings and four undecided objects are not a claim of a clean forest.

### Measured ownership volume on ad.lab, 2026-09-05

**This is the five-operator ownership comparison, not P-145.** That row needs control edges and
their expected/unexpected/unknown classifications, which were not implemented when this comparison
was performed. The later initial-slice measurements are in the judgement-store document; they do
not turn this ownership comparison into a P-145 acceptance pass.

**This subsection preserves the earlier schema-8 comparison, before the scoped correction.** The
subsequent schema-9 result and the resolution of P-147 are recorded immediately above it; these
historical version numbers do not state the current derivation schema.

**One capture, two policies.** The CLI captured ad.lab-20260905-212426: three domains and 8,383
objects. A copy of that sealed evidence was derived and judged with 548, 549, 550, 551 and 552
temporarily added to `ProtectedGroupCatalogue.AcceptedOwnerRids`. After restoring the original
source exactly, the original bundle was derived and judged again. This isolates the five groups;
it is not a rollback of every change made by `0107` or a comparison with the predecessor.

The existing `next/tools/explain-derivation.ps1`, `next/tools/judge-bundle.ps1` and
`next/tools/show-findings.ps1` produced and read both results. No throwaway test class or directory
modification was used. The artifacts are in next/artifacts/ownership-volume-20260905/.

| Rule | Five operator groups accepted | Current policy | New findings |
|---|---:|---:|---:|
| SEC-031 | 1,788 | 1,788 | 0 |
| SEC-032 | 0 | 0 | 0 |

**Both rules reached 8,379 verdicts and could not decide four objects, under both policies.** Their
stored outcome is `Indeterminate`, with `ProtectedPrincipals.MembershipIncomplete` recorded for
each rule. These are reported findings, not a claim that every object was judged. The derivation
records four unresolved protection answers: three with `PrimaryGroupTraversalResearchBlocked` and
one with `PrincipalClaimDisputed`. The separate owner-acceptance answer was not unknown.

**The policy switch was observed, not assumed.** Reading the persisted derivations back gave 29
accepted principals before and 13 afterwards. The sixteen changed answers are the five operator
groups in each of the three domains and one account reached through Backup Operators. Both complete
ownership reports, including finding text and targets, are identical after excluding their
bundle/store headers. There are therefore no new findings from this comparison to call wrong.

**What the 1,788 findings are actually about:**

| Owner and target | SEC-031 findings, under both policies |
|---|---:|
| Schema Admins owning the schema partition itself or its descendants | 1,778 |
| Computer accounts owning Windows Virtual Machine service-connection records | 8 |
| BADC and PHDC owning domain-reference objects in the configuration partition | 2 |

**The first 1,778 exposed the reporting defect P-147, not a five-operator volume increase.**
The finding said Schema Admins was *not an administrative principal* on the very schema that
[Microsoft's security-groups reference](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups#schema-admins)
gives it full administrative access to. That was misleading, not merely verbose. The target-scope
decision was subsequently accepted and implemented as `0109`; the current run no longer emits
those 1,778 findings. The ten machine-owned objects carry the stated ownership, but
this measurement does not establish that their ownership is improper or evidence of abuse.

**Verdict at the time of the five-group comparison: no observed increase, but not ready for stage 6.** The
existing Schema Admins volume is already the failure this check was meant to catch. It is recorded
as high severity on P-147; it was subsequently corrected by scoped acceptance under 0109, measured
above, rather than by suppressing findings. This small lab result cannot establish the impact in a forest with years of operator-group
delegation, and the four undecided objects remain undecided.

**Reproducibility:** both evidence files retained SHA-256
2DEF9F8AD4DE01877970B7F97F845716C1FFC1B093B01F388004610526E76BE4. The before derivation generation is
066e66ca-3cc6-48dd-bf00-0b66b4fe3bcc and its judgement generation is
338e54a1-e0fe-4d0a-ae76-261a74e2b5f2. The after generations are
0f3b1913-434e-4a1c-8a03-f72185e537ff and b5abf116-8918-4d44-aa09-492c80d059b9 respectively.
Both derivations in this earlier comparison use schema 8. At its conclusion the temporary catalogue
change was restored and its source hash matched the pre-measurement hash; scoped acceptance was
implemented afterwards.

**A high-severity verification defect was found and fixed during the comparison.**
`ObjectOwnershipRuleTests.OwnershipAndTheControlPlaneClassifyTheSameIdentifierCompatibly` stayed
green while all five operator groups were accepted. Its owner fixture gave built-in groups a null
domain, so the rule's domain-scoped lookup never read the supplied acceptance. Correcting the
fixture in `ObjectOwnershipRuleTests` made the widened policy fail with
*S-1-5-32-548 is outside the control plane under 0099, so ownership must report it.* Restoring the
then-current policy made all 24 ownership-rule tests in that comparison pass. The test still compares against the
repository's written-out `0099` set, not Microsoft's specifications or the unbuilt control-plane
catalogue. It must be retargeted when that catalogue is built; this fixture repair does not discharge
that obligation.

---

**A question the owner has already answered is a defect in this repository.** When he answers one,
it belongs here, in the same turn.
