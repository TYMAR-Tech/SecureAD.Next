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
| Judge | Stream the bundle once, offer every object to every scheduled rule, write findings to a separate store | built, 17 rules |
| Read back | Run library, directory tree, object detail and findings | built |
| Dashboard | Coverage and inventory: how much of the forest was read, and what it held | built |
| Reports, compare and export | — | not built |

**The counts and states in that table are checked rather than maintained by hand**, by
`next/tools/check-stage-status.ps1`. A status goes false when the code moves and the document sits
still, so it cannot be protected by proof-reading; this file claimed *two rules* for long enough
that twelve more were built underneath it. See `P-135`, and `ROADMAP.md` § *Where we are* for the
per-stage witnesses.

`0008` fixes the boundary: **the only component that touches a domain controller is capture.** A
screen showing a permission is reading a file, not asking the directory.

**The application is the product; the command line runs unattended.** The owner's words, 2026-08-26:
*"this whole app is a GUI, the cli is just to capture overnight."* The GUI is where an operator
works and is what every screen is designed for. The command line exists so a long run can happen
overnight without the application open, and **it is intended to grow judging too** — the owner,
later the same day: *"i will be making it so the user can run the audit and it complete the judging
via CLI, so it can run overnight."* So the command line is not capture-only forever; it is the
unattended path, and the GUI is the worked path.

## How judging works

Decided, built and measured — see [`layers/judgement/`](layers/judgement/).

- **One pass over the bundle, not one per rule.** Every object is streamed once and offered to every
  scheduled rule while it is in hand, so judging forty rules costs the same read as judging one.
- **A rule judges one object and nothing else.** No forest, no sibling lookup, no second pass, so a
  rule cannot quietly acquire an input it never declared.
- **A rule declares the data it reads, or the build fails** (`0083`).
- **Atomic per rule, not per run.** A rule that throws loses only itself; its partial findings are
  discarded, because a partial verdict would read as a complete one.
- **Findings live outside the seal** (`0085`), in a store that is disposable and rebuildable.

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
[implementation record](layers/judgement/the-judgement-store.md#bounded-effective-member-attribution)
records the final artifacts and outstanding acceptance boundaries. No production expansion budget is approved.
General membership writes and own-account-only Self-Membership candidates are separate; concrete
requester answers are not implied by those candidates. Historical schema-16 Self-Membership
candidates remain Unknown, and no general member capabilities are expanded.
The owner-to-DACL transition remains unknown and uncounted. Current judgement schema 24 stores this
product, the bounded Self-Membership requester assessments introduced in schema 17, and discovery
coverage introduced in schema 18; schema 19/control engine 3 introduced reset permission, and
schema 20/control engine 4 added key-credential write permission and the property-set evidence safeguard;
schema 21/control engine 5 added the two replication capabilities on captured naming-context roots;
schema 22/control engine 6 added existing-owner assessments and replay-validated ownership proof;
schema 23/control engine 7 adds bounded full-control summaries with separate source proof and counting links;
schema 24/control engine 8 adds explicitly budgeted member attribution, requiring current Derivation inputs;
principal catalogue version 2 includes the verified BUILTIN domain-scope correction, P-150.
At the catalogue-2 checkpoint, re-judging alone obtained that correction. The current member-attribution
product requires current Derivation inputs: re-derive and re-judge an isolated copy, without re-capture.
The [judgement-store document](layers/judgement/the-judgement-store.md#p-150-corrected--catalogue-2-2026-09-06)
records the implementation and before/after lab checks. P-145 now has initial-slice measurements,
not an acceptance pass: the remaining capabilities, member-attribution scale measurements, Tier 0-target review and
claim-specific laboratory gates remain outstanding. The
[membership slice](layers/judgement/the-judgement-store.md#bounded-group-membership-control--schema-16)
has automated coverage, an isolated offline comparison and an
[isolated live Self-Membership measurement](layers/judgement/the-judgement-store.md#isolated-live-self-membership-measurement--2026-09-06).
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
The [bounded implementation preparation](layers/judgement/the-judgement-store.md#password-reset-control--bounded-implementation-preparation)
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
The [implementation record](layers/judgement/the-judgement-store.md#key-credential-write-permission--bounded-implementation)
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
The [implementation record](layers/judgement/the-judgement-store.md#replication-permissions--bounded-implementation)
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
The [ownership implementation record](layers/judgement/the-judgement-store.md#ownership-control--bounded-implementation)
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
The [implementation record](layers/judgement/the-judgement-store.md#full-control-aggregation--bounded-implementation)
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
[review status](layers/judgement/the-judgement-store.md#authorization-correction-and-remaining-review-findings).
This is not a complete token model, whole-feature acceptance or a new live acceptance result.

**R7 presentation approved after the performance checkpoint:** the owner selected
"Approve the recommended table wording and expandable selected-answer evidence". Keep the existing
table, approved sizing and scrolling; show plain-language authorization, own-account restriction and
readiness separately, with expandable stored identities, permission entries and direct/group route
for the selected answer. Keep capture-wide coverage limitations separate. This approves presentation
only, not discovery enablement, a numerical budget, authorization/storage changes or R8 acceptance.
Implementation and offline validation are recorded in the
[Assets specification](layers/shell/the-assets-screen.md#r7-requester-presentation).
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
completed chains toward Tier 0. The [R8 record](layers/judgement/the-judgement-store.md#r8-current-state-reconciliation)
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
and their limitations are recorded in [the judgement store](layers/judgement/the-judgement-store.md).
This is not approval of a numerical limit, enabling automatic discovery, new authorization behavior,
a new R7 presentation design or final feature acceptance. Laptop/monitor checks remain ordinary
verification work, not an additional session that must precede continued development.

**Session checkpoint requested by the owner:** update the governing documents, commit and push the
validated work, then resume in a new session. This explicitly authorizes that checkpoint commit and
push; it did not approve the then-proposed R7 requester-details presentation. The continuation session
obtained explicit approval before implementation; see the
[R7 presentation record](layers/shell/the-assets-screen.md#r7-requester-presentation).
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
| Control edges the predecessor produced | ~9 million |
| Delegations | ~1.3 million |
| Findings | ~34,000 |
| Directory depth | deep, average distinguished name about 97 characters |

**Where these come from, exactly.** They were first found in the predecessor's
`tests/SecureAD.Infrastructure.Tests/Performance/ObjectDetailProfiler.cs`, which states them as the
production environment it profiles against. **The owner confirmed them as still correct on
2026-09-07.** They are the shape to design and measure against.

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
run took three to five hours.** Capture was never the problem. The time went on the graph.

Its own CONTROL-EDGES-AND-PATHS document, under docs/ in the predecessor tree, says how, and it is
costs stacked on each other:

- **`fact_group_membership_closure`** — the full transitive closure of every group, materialised.
  Quadratic in the forest.
- **"Traversal: BFS from each non-high-value principal to discover shortest paths to targets."**
  With a hundred thousand principals that is a hundred thousand traversals of a graph holding
  millions of edges.

**Neither is required by the question being asked.** *Who can reach Tier 0* is answered by walking
**backwards from the targets** — there are perhaps dozens of high-value targets against a hundred
thousand principals, so the same answers cost three or four orders of magnitude less. The old
application even built the reverse graph, as step 3 of that document, and then traversed forward
from every principal anyway.

**So the hours were an algorithmic choice, not the price of the analysis.** This matters now because
escalation paths are unbuilt here and will be asked for eventually. Two things follow:

- The closure is already refused: `what-stage-2a-derives.md` walks membership on demand, because
  *the transitive closure of every group is quadratic in a real forest, while every consumer asks
  about a handful of named principals*. That decision was taken for a different reason and happens
  to remove the first cost entirely.
- **When paths are built, traverse from the targets.** Reverse traversal needs `memberOf` edges,
  which are linear in memberships and already persisted, and never needs the closure.

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
[`layers/shell/what-a-run-counted.md`](layers/shell/what-a-run-counted.md).

**Tier 1 means what Microsoft says it means, decided 2026-09-05.** Per the
[tier model](https://learn.microsoft.com/windows-server/identity/ad-ds/tier-model), Tier 1 is
*enterprise servers and applications*: member servers and server administrator roles, the solutions
that manage them (backup, monitoring, patching, hypervisors), Microsoft server applications such as
Exchange, SharePoint and SQL Server, third-party server solutions, and line-of-business
applications. Tier 2 is end-user devices and accounts. This settles the wording of `SEC-073` and
`SEC-074`, which were recorded as *gap - Tier1 undefined*.

**It does not settle how the product decides which computers those are, and that is the harder
half.** Tier 0 is derivable from the directory - Microsoft names the groups. **Tier 1 is not.**
Nothing in Active Directory marks a member server as an Exchange server or a line-of-business host;
the tier model is an operational structure an organisation adopts, expressed in OUs and groups it
chose the names of. `operatingSystem` distinguishes a server from a workstation and says nothing
about what it carries. So a Tier 1 rule must either read a customer-supplied definition or infer
one, and **inferring it would be this product asserting a tier boundary the customer never drew**.
Recorded as `F-S45-11`; not blocking the dashboard.

**Group Policy is deferred to the end, decided 2026-09-05.** The owner: *"i may leave until the end
unless it will be harder then but i dont see why it would be."* **It will not be harder later**, and
the reason is worth recording: the five GPO rules are blocked on a capability the product does not
have - reading policy *content* out of files on SYSVOL, rather than reading the policy object in the
directory. That capability is self-contained, it is the same amount of work whenever it is done, and
nothing else in the roadmap depends on it. Deferring it costs nothing but the findings themselves.

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

The classification and declaration mechanisms remain implementation work on P-142 and P-143.

**Customers may declare Tier 0 assets, never Tier 0 principals.** Declaring an asset adds something
to watch and hides nothing. Declaring a principal would hide edges by default and make conclusions
depend on local configuration. A specific edge that is fine here is handled by accepting the finding,
which stays on the record. **A declaration never moves a severity** - that is fixed by the rule
(`0066`, `0082`).

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
`pwsh`, derived and judged `next/artifacts/membership-routes-0108/`. SEC-031 remains **10**, SEC-032
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
initial-slice output, and its measured P-150 correction is linked above. P-145 remains open for the
remaining acceptance work, not for lack of any control-edge output. The ten remaining ownership
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

